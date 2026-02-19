import base64
import json
import os
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from jose import jwt
from jose.exceptions import JWTError

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

app = FastAPI(title="CIZ Verifier")

KC_BASE = os.getenv("KC_BASE", "").rstrip("/")
REALM = os.getenv("REALM", "vc-demo")

# did:web for this verifier host
DID_WEB = os.getenv("DID_WEB", "did:web:ciz-verifier.vuggie.net")
VERIFIER_KEY_PATH = os.getenv("VERIFIER_KEY_PATH", "/data/verifier-ec256.pem")

# (optional) expectations
EXPECTED_VC_CONFIG_ID = os.getenv("EXPECTED_VC_CONFIG_ID", "")
EXPECTED_ISSUER = os.getenv("EXPECTED_ISSUER", "")  # if set, enforce issuer claim

# Stable verifier key (only for DID doc / optional signing)
VERIFIER_PRIVATE_KEY: Optional[ec.EllipticCurvePrivateKey] = None
VERIFIER_PUBLIC_JWK: Optional[Dict[str, Any]] = None


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_or_create_verifier_keypair() -> None:
    """
    Persist a P-256 key so the verifier DID document stays stable across restarts.
    (Not required for verifying, but useful for did:web.)
    """
    global VERIFIER_PRIVATE_KEY, VERIFIER_PUBLIC_JWK

    try:
        if os.path.exists(VERIFIER_KEY_PATH):
            with open(VERIFIER_KEY_PATH, "rb") as f:
                pem = f.read()
            VERIFIER_PRIVATE_KEY = serialization.load_pem_private_key(pem, password=None)
        else:
            VERIFIER_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
            os.makedirs(os.path.dirname(VERIFIER_KEY_PATH), exist_ok=True)
            pem = VERIFIER_PRIVATE_KEY.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(VERIFIER_KEY_PATH, "wb") as f:
                f.write(pem)
    except Exception:
        # fallback: in-memory key
        VERIFIER_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())

    pub = VERIFIER_PRIVATE_KEY.public_key()
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")

    VERIFIER_PUBLIC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(x),
        "y": b64url(y),
        "use": "sig",
        "alg": "ES256",
        "kid": "ciz-verifier-key-1",
    }


@app.on_event("startup")
def _startup() -> None:
    load_or_create_verifier_keypair()


@app.get("/")
def health():
    return {"ok": True, "service": "ciz-verifier"}


@app.get("/.well-known/did.json")
def did_document():
    if VERIFIER_PUBLIC_JWK is None:
        load_or_create_verifier_keypair()

    did_doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": DID_WEB,
        "verificationMethod": [
            {
                "id": f"{DID_WEB}#key-1",
                "type": "JsonWebKey2020",
                "controller": DID_WEB,
                "publicKeyJwk": VERIFIER_PUBLIC_JWK,
            }
        ],
        "authentication": [f"{DID_WEB}#key-1"],
        "assertionMethod": [f"{DID_WEB}#key-1"],
    }
    return JSONResponse(did_doc, media_type="application/did+json")


async def get_jwks() -> Dict[str, Any]:
    oidc = f"{KC_BASE}/realms/{REALM}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(oidc)
        r.raise_for_status()
        jwks_uri = r.json()["jwks_uri"]
        r2 = await client.get(jwks_uri)
        r2.raise_for_status()
        return r2.json()


@app.post("/verify")
async def verify(vp: Dict[str, Any]):
    """
    Minimal verifier:
    - expects VP JSON with:
        {
          "type": "VerifiablePresentation",
          "holder": {<holder public jwk or did>},
          "verifiableCredential": "<jwt>"
        }
    - verifies VC JWT signature against Keycloak realm JWKS
    """
    vc_jwt = vp.get("verifiableCredential")
    holder = vp.get("holder")

    if not vc_jwt:
        return {"ok": False, "error": "missing verifiableCredential"}

    jwks = await get_jwks()

    try:
        # Verify VC signature (issuer = Keycloak signing key)
        claims = jwt.decode(vc_jwt, jwks, options={"verify_aud": False})
    except JWTError as e:
        return {"ok": False, "error": "vc_signature_invalid", "details": str(e)}

    # Optional issuer check
    if EXPECTED_ISSUER:
        iss = claims.get("iss")
        if iss != EXPECTED_ISSUER:
            return {"ok": False, "error": "issuer_mismatch", "expected": EXPECTED_ISSUER, "got": iss}

    # Optional: check VC config id if your VC includes it (implementation-specific)
    # (Many jwt_vc payloads do not include this directly; depends on Keycloak mapping.)
    config_ok = True
    if EXPECTED_VC_CONFIG_ID:
        # naive heuristic: look in "vc" -> "type" or custom claim
        vc_obj = claims.get("vc") or {}
        types = vc_obj.get("type") or []
        config_ok = (EXPECTED_VC_CONFIG_ID in types) or (claims.get("credential_configuration_id") == EXPECTED_VC_CONFIG_ID)

    return {
        "ok": True,
        "holder_present": bool(holder),
        "vc_config_check": config_ok,
        "vc_claims": claims,
    }
