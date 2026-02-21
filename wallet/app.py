import secrets
from urllib.parse import urlencode
import base64
import json
import os
import time
import threading
from typing import Any, Dict, Optional, List
from pydantic import BaseModel

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
from jose import jwt

"""
Zorgkantoor Wallet (demo)

Roles in the demo:
- Holder/Wallet: Zorgkantoor (this service)
- Issuer + Token service (AS): Vecozo (Keycloak for tokens; separate issuer-service for credential issuance)
- Verifier: CIZ (optional: simple /present POST to a verifier endpoint)

Key piece your getToken.sh expects:
- POST /make-proof  -> returns { proof_jwt: "...", jwk: {...} }
"""

app = FastAPI(title="Zorgkantoor Wallet (OID4VCI Demo)")

# --- Vecozo (Keycloak) token service (AS) ---
KC_BASE = os.getenv("KC_BASE", "").rstrip("/")
REALM = os.getenv("REALM", "vc-demo")
WALLET_CLIENT_ID = os.getenv("WALLET_CLIENT_ID", "zorgkantoor-wallet")
VC_CONFIG_ID = os.getenv("VC_CONFIG_ID", "membership-credential")

REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:3000/callback")
REQUESTED_SCOPE = os.getenv("REQUESTED_SCOPE", f"openid {VC_CONFIG_ID}")

# --- Vecozo issuer-service (separate from Keycloak), e.g. http://localhost:8081 ---
ISSUER_CRED_EP = os.getenv("ISSUER_CRED_EP", "").rstrip("/")  # if set, prefer this over KC metadata

# --- CIZ verifier endpoint (optional) ---
CIZ_VERIFIER_URL = os.getenv("CIZ_VERIFIER_URL", "").strip()

# Proof format knobs (interop)
# Many issuers accept either:
# - DID-based kid (did:web:...#key-1) and resolve the DID, OR
# - JWK-in-header and/or cnf.jwk in request
# For a localhost demo issuer, JWK-in-header is usually easiest.
PROOF_KID_MODE = os.getenv("PROOF_KID_MODE", "jwk").lower().strip()  # "jwk" or "did"

OAUTH_STATE: Optional[str] = None
PKCE_VERIFIER: Optional[str] = None
LAST_TOKEN: Optional[Dict[str, Any]] = None

# DID:web for this wallet (must match your DNS/HTTPS host if you use did mode)
DID_WEB = os.getenv("DID_WEB", "did:web:zorgkantoor-wallet.localhost")
# Persist holder private key so holder key is stable across restarts (mount /data as a volume in Docker)
HOLDER_KEY_PATH = Path(os.getenv("HOLDER_KEY_PATH", "/data/holder-ec256.pem"))

# Persist issued credentials (simple demo wallet store)
CRED_STORE_PATH = Path(os.getenv("CRED_STORE_PATH", "/data/credentials.json"))
_WALLET_STORE_LOCK = threading.Lock()
WALLET_VC_STORE: List[str] = []

HOLDER_PRIVATE_KEY: Optional[ec.EllipticCurvePrivateKey] = None
HOLDER_PUBLIC_JWK: Optional[Dict[str, Any]] = None


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_verifier() -> str:
    # RFC7636: 43-128 chars; url-safe
    return b64url(os.urandom(32))  # ~43 chars


def pkce_challenge(verifier: str) -> str:
    import hashlib
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _public_jwk_from_private(priv: ec.EllipticCurvePrivateKey) -> Dict[str, Any]:
    pub = priv.public_key()
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(x),
        "y": b64url(y),
        "use": "sig",
        "alg": "ES256",
        # Stable key id for demo (also used in cnf.jwk)
        "kid": "wallet-key-1",
    }


def ensure_holder_keys(force_new: bool = False) -> None:
    global HOLDER_PRIVATE_KEY, HOLDER_PUBLIC_JWK

    if HOLDER_PRIVATE_KEY is not None and HOLDER_PUBLIC_JWK is not None and not force_new:
        return

    if HOLDER_KEY_PATH.exists() and not force_new:
        pem = HOLDER_KEY_PATH.read_bytes()
        HOLDER_PRIVATE_KEY = serialization.load_pem_private_key(pem, password=None)
        HOLDER_PUBLIC_JWK = _public_jwk_from_private(HOLDER_PRIVATE_KEY)
        return

    HOLDER_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
    HOLDER_PUBLIC_JWK = _public_jwk_from_private(HOLDER_PRIVATE_KEY)

    try:
        HOLDER_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        pem = HOLDER_PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        HOLDER_KEY_PATH.write_bytes(pem)
    except Exception:
        pass


def _pem_private_key() -> bytes:
    assert HOLDER_PRIVATE_KEY is not None
    return HOLDER_PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


async def get_oidc_endpoints() -> Dict[str, str]:
    if not KC_BASE:
        raise HTTPException(status_code=500, detail="KC_BASE is not set")
    url = f"{KC_BASE}/realms/{REALM}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url)
        r.raise_for_status()
        j = r.json()
    return {
        "authorization_endpoint": j["authorization_endpoint"],
        "token_endpoint": j["token_endpoint"],
        "jwks_uri": j["jwks_uri"],
        "issuer": j["issuer"],
    }


async def get_keycloak_issuer_metadata() -> Dict[str, Any]:
    if not KC_BASE:
        raise HTTPException(status_code=500, detail="KC_BASE is not set")
    url = f"{KC_BASE}/realms/{REALM}/.well-known/openid-credential-issuer"
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()


def load_wallet_store() -> None:
    """Load stored credentials from disk (best-effort)."""
    global WALLET_VC_STORE
    try:
        if CRED_STORE_PATH.exists():
            data = json.loads(CRED_STORE_PATH.read_text())
            if isinstance(data, list):
                WALLET_VC_STORE = [x for x in data if isinstance(x, str)]
    except Exception:
        # best-effort for demo
        WALLET_VC_STORE = []


def save_wallet_store() -> None:
    """Persist stored credentials to disk (best-effort)."""
    try:
        CRED_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CRED_STORE_PATH.write_text(json.dumps(WALLET_VC_STORE))
    except Exception:
        pass


def make_proof_jwt(aud: str, nonce: Optional[str]) -> str:
    """
    Creates OpenID4VCI proof JWT signed by the holder key.

    Interop notes:
    - typ SHOULD be "openid4vci-proof+jwt"
    - aud MUST match the credential endpoint exactly
    - nonce MUST be the c_nonce from issuer response (when provided)
    - Some issuers prefer JWK-in-header (mode=jwk), others resolve DID-based kid (mode=did).
    """
    ensure_holder_keys()
    assert HOLDER_PRIVATE_KEY is not None and HOLDER_PUBLIC_JWK is not None

    now = int(time.time())
    claims: Dict[str, Any] = {
        "aud": aud,
        "iat": now,
    }
    if nonce:
        claims["nonce"] = nonce

    headers: Dict[str, Any] = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
    }

    if PROOF_KID_MODE == "did":
        # DID-native kid reference (issuer must resolve did:web to get the key)
        claims["iss"] = DID_WEB
        headers["kid"] = f"{DID_WEB}#key-1"
    else:
        # JWK-in-header mode (works well for localhost issuers)
        headers["kid"] = HOLDER_PUBLIC_JWK.get("kid", "wallet-key-1")
        headers["jwk"] = HOLDER_PUBLIC_JWK

    return jwt.encode(claims, _pem_private_key(), algorithm="ES256", headers=headers)


@app.on_event("startup")
async def _startup():
    ensure_holder_keys()
    load_wallet_store()


@app.get("/health")
async def health():
    return {"ok": True, "role": "wallet", "holder": "zorgkantoor"}


@app.get("/demo")
async def demo_info():
    return {
        "holder": {"name": "Zorgkantoor", "did": DID_WEB, "proof_kid_mode": PROOF_KID_MODE},
        "issuer": {"name": "Vecozo", "credential_endpoint": ISSUER_CRED_EP or "(via Keycloak metadata)"},
        "token_service": {"name": "Vecozo (Keycloak)", "kc_base": KC_BASE, "realm": REALM},
        "verifier": {"name": "CIZ", "verifier_url": CIZ_VERIFIER_URL or None},
        "vc_config_id": VC_CONFIG_ID,
    }


@app.post("/make-proof")
async def make_proof(payload: Dict[str, Any]):
    """
    Return an OpenID4VCI proof JWT signed by the Zorgkantoor holder key.

    Expected JSON body:
      { "aud": "http://localhost:8081/credential", "nonce": "<c_nonce>" }

    Response includes the public JWK so your script can also send cnf.jwk.
    """
    aud = (payload or {}).get("aud")
    nonce = (payload or {}).get("nonce")

    if not aud or not isinstance(aud, str):
        raise HTTPException(status_code=400, detail="Missing required field: aud")
    if nonce is not None and not isinstance(nonce, str):
        raise HTTPException(status_code=400, detail="Field 'nonce' must be a string when provided")

    proof_jwt = make_proof_jwt(aud=aud, nonce=nonce)
    ensure_holder_keys()
    assert HOLDER_PUBLIC_JWK is not None
    return {"proof_jwt": proof_jwt, "jwk": HOLDER_PUBLIC_JWK, "holderKid": f"{DID_WEB}#key-1"}


@app.post("/store")
async def store_credential(payload: Dict[str, Any]):
    """Store an issued credential in the wallet."""
    cred = (payload or {}).get("credential")
    if not cred or not isinstance(cred, str):
        raise HTTPException(status_code=400, detail="Missing credential")
    with _WALLET_STORE_LOCK:
        WALLET_VC_STORE.append(cred)
        save_wallet_store()
        return {"stored": True, "count": len(WALLET_VC_STORE)}


@app.get("/credentials")
async def list_credentials():
    """List stored credentials."""
    with _WALLET_STORE_LOCK:
        return {"count": len(WALLET_VC_STORE), "credentials": WALLET_VC_STORE}


@app.get("/credentials/latest")
async def latest_credential():
    """Get latest stored credential."""
    with _WALLET_STORE_LOCK:
        if not WALLET_VC_STORE:
            raise HTTPException(status_code=404, detail="No credentials stored")
        return {"credential": WALLET_VC_STORE[-1]}


@app.get("/init")
async def init_wallet():
    ensure_holder_keys(force_new=True)
    return {"holder_public_jwk": HOLDER_PUBLIC_JWK, "did": DID_WEB}


@app.get("/.well-known/did.json")
async def did_document():
    """Only needed if PROOF_KID_MODE=did."""
    ensure_holder_keys()
    did_doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": DID_WEB,
        "verificationMethod": [
            {
                "id": f"{DID_WEB}#key-1",
                "type": "JsonWebKey2020",
                "controller": DID_WEB,
                "publicKeyJwk": HOLDER_PUBLIC_JWK,
            }
        ],
        "authentication": [f"{DID_WEB}#key-1"],
        "assertionMethod": [f"{DID_WEB}#key-1"],
    }
    return JSONResponse(did_doc, media_type="application/did+json")


@app.post("/present")
async def present_to_verifier(payload: Dict[str, Any]):
    """
    Lightweight demo presentation helper (NOT full OID4VP).
    Body: { "verifier_url": "...", "credential": "<jwt>" }
    """
    verifier_url = (payload or {}).get("verifier_url") or CIZ_VERIFIER_URL
    credential = (payload or {}).get("credential")

    if not verifier_url:
        raise HTTPException(status_code=400, detail="Missing verifier_url and CIZ_VERIFIER_URL not set")
    if not credential:
        raise HTTPException(status_code=400, detail="Missing credential")

    ensure_holder_keys()
    vp = {
        "type": "VerifiablePresentation",
        "holder": DID_WEB,
        "verifiableCredential": credential,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(verifier_url, json=vp)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return {"status_code": r.status_code, "verifier_response": body}


class VPRequest(BaseModel):
    verifier_aud: str = "ciz-verifier"
    nonce: str | None = None  # optional
    vc_jwt: str | None = None # optional; if omitted use latest stored VC

@app.post("/make-vp")
async def make_vp(req: VPRequest):
    # pick VC to present
    vc_jwt = req.vc_jwt
    if not vc_jwt:
        # use latest stored if you have persistence; otherwise you can require vc_jwt
        try:
            vc_jwt = WALLET_VC_STORE[-1]
        except Exception:
            raise HTTPException(status_code=400, detail="No VC available in wallet; store one first")

    ensure_holder_keys()
    now = int(time.time())

    vp_claims = {
        "iss": DID_WEB,
        "aud": req.verifier_aud,
        "iat": now,
        "vp": {
            "type": "VerifiablePresentation",
            "holder": DID_WEB,
            "verifiableCredential": [vc_jwt],
        },
    }
    if req.nonce:
        vp_claims["nonce"] = req.nonce

    headers = {"typ": "vp+jwt", "alg": "ES256", "kid": f"{DID_WEB}#key-1"}
    vp_jwt = jwt.encode(vp_claims, _pem_private_key(), algorithm="ES256", headers=headers)
    return {"vp_jwt": vp_jwt}

