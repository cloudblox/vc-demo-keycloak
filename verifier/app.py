import os
import json
import base64
from typing import Any, Dict, Optional, List

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from jose import jwt
from jose.utils import base64url_decode

app = FastAPI(title="CIZ Verifier (VP-gated Hello World)")

# Vecozo (Keycloak realm) - used to verify VC signatures
EXPECTED_ISSUER = os.getenv("EXPECTED_ISSUER", "").rstrip("/")
ISSUER_JWKS_URL = os.getenv("ISSUER_JWKS_URL", "")  # e.g. https://.../realms/<realm>/protocol/openid-connect/certs
EXPECTED_VC_TYPE = os.getenv("EXPECTED_VC_TYPE", "ZorgkantoorCredential")

# Holder DID (Zorgkantoor wallet) - used to verify VP signature
EXPECTED_HOLDER_DID = os.getenv("EXPECTED_HOLDER_DID", "did:web:zorgkantoor-wallet.vuggie.net")
# Our verifier audience that the wallet should set as aud in the vp_jwt (optional but recommended)
VERIFIER_AUD = os.getenv("VERIFIER_AUD", "ciz-verifier")

# Cache
_JWKS_CACHE: Optional[Dict[str, Any]] = None


class HelloRequest(BaseModel):
    vp_jwt: str


def _b64url_json(segment: str) -> Dict[str, Any]:
    seg = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.encode("ascii")).decode("utf-8"))


async def fetch_jwks(url: str) -> Dict[str, Any]:
    global _JWKS_CACHE
    if _JWKS_CACHE is not None:
        return _JWKS_CACHE
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url)
        r.raise_for_status()
        _JWKS_CACHE = r.json()
        return _JWKS_CACHE


async def resolve_did_web(did: str) -> Dict[str, Any]:
    # did:web:example.com -> https://example.com/.well-known/did.json
    if not did.startswith("did:web:"):
        raise HTTPException(status_code=400, detail=f"Only did:web supported in demo, got {did}")
    host = did[len("did:web:"):]
    url = f"https://{host}/.well-known/did.json"
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()


def find_vm_jwk(did_doc: Dict[str, Any], kid: str) -> Dict[str, Any]:
    vms = did_doc.get("verificationMethod", []) or []
    for vm in vms:
        if vm.get("id") == kid and vm.get("publicKeyJwk"):
            return vm["publicKeyJwk"]
    raise HTTPException(status_code=401, detail=f"Holder key {kid} not found in DID doc")


async def verify_vp_jwt(vp_jwt: str) -> Dict[str, Any]:
    parts = vp_jwt.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=400, detail="vp_jwt is not a JWS")

    header = _b64url_json(parts[0])
    kid = header.get("kid")
    if not kid or not isinstance(kid, str):
        raise HTTPException(status_code=401, detail="vp_jwt header.kid missing")

    # Expected kid should belong to our expected holder DID
    if not kid.startswith(EXPECTED_HOLDER_DID):
        raise HTTPException(status_code=401, detail=f"vp_jwt kid is not from expected holder DID ({EXPECTED_HOLDER_DID})")

    did_doc = await resolve_did_web(EXPECTED_HOLDER_DID)
    holder_jwk = find_vm_jwk(did_doc, kid)

    # Verify signature + standard JWT validations
    try:
        claims = jwt.decode(
            vp_jwt,
            holder_jwk,
            algorithms=["ES256"],
            options={"verify_aud": False},  # we'll check aud ourselves
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"vp_jwt signature/claims invalid: {e}")

    # Optional checks
    aud = claims.get("aud")
    if aud and aud != VERIFIER_AUD:
        raise HTTPException(status_code=401, detail=f"vp_jwt aud mismatch (got {aud}, expected {VERIFIER_AUD})")

    iss = claims.get("iss")
    if iss != EXPECTED_HOLDER_DID:
        raise HTTPException(status_code=401, detail=f"vp_jwt iss mismatch (got {iss}, expected {EXPECTED_HOLDER_DID})")

    vp = claims.get("vp")
    if not isinstance(vp, dict):
        raise HTTPException(status_code=401, detail="vp_jwt missing vp object")

    vcs = vp.get("verifiableCredential")
    if not isinstance(vcs, list) or not vcs or not isinstance(vcs[0], str):
        raise HTTPException(status_code=401, detail="vp.verifiableCredential must be a list of JWT strings")

    return {"claims": claims, "vc_jwt": vcs[0]}


async def verify_vc_jwt(vc_jwt: str) -> Dict[str, Any]:
    if not ISSUER_JWKS_URL:
        raise HTTPException(status_code=500, detail="ISSUER_JWKS_URL not configured")
    jwks = await fetch_jwks(ISSUER_JWKS_URL)

    try:
        claims = jwt.decode(
            vc_jwt,
            jwks,
            algorithms=["ES256"],
            audience=None,
            options={"verify_aud": False},
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"VC signature/claims invalid: {e}")

    if EXPECTED_ISSUER:
        iss = claims.get("iss")
        if iss != EXPECTED_ISSUER:
            raise HTTPException(status_code=401, detail=f"VC iss mismatch (got {iss}, expected {EXPECTED_ISSUER})")

    vc = claims.get("vc") or {}
    types = vc.get("type") or []
    if EXPECTED_VC_TYPE and EXPECTED_VC_TYPE not in types:
        raise HTTPException(status_code=401, detail=f"VC type mismatch (missing {EXPECTED_VC_TYPE})")

    # Optional: check cnf binding exists
    cnf = claims.get("cnf") or claims.get("vc", {}).get("cnf") or {}
    # Your JWT-VC example showed cnf at top-level: claims["cnf"]["kid"]
    if "kid" not in (claims.get("cnf") or {}):
        # not fatal for demo, but helpful to enforce if you want
        pass

    return claims


@app.get("/health")
async def health():
    return {"ok": True, "service": "ciz-verifier"}


@app.post("/hello")
async def hello(req: HelloRequest):
    vp_verified = await verify_vp_jwt(req.vp_jwt)
    vc_claims = await verify_vc_jwt(vp_verified["vc_jwt"])

    # If we got here: VP + VC validated
    return {
        "message": "Hello World",
        "holder": vc_claims.get("sub"),
        "issuer": vc_claims.get("iss"),
        "vc_type": (vc_claims.get("vc") or {}).get("type"),
    }
