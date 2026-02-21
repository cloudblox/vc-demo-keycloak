#!/usr/bin/env bash
set -euo pipefail
set -a
source .env
set +a

WALLET_STORE_EP="http://localhost:3000/store"

############################################
# OID4VCI (pre-auth) -> VC issuance (JWT_VC)
# Uses USERNAME2 to avoid shell collisions
############################################

# --- REQUIRED CONFIG ---
KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo}"

# Keycloak token endpoint
TOKEN_EP="$KC_BASE/realms/$REALM/protocol/openid-connect/token"

# Keycloak offer handle endpoint (realm-scoped; works but may log "deprecated")
OFFER_HANDLE_EP="$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer-uri"

# Prefer well-known issuer metadata endpoint (newer form)
WELLKNOWN_EP="${WELLKNOWN_EP:-$KC_BASE/.well-known/openid-credential-issuer/realms/$REALM}"

# Your wallet client_id (Keycloak client)
WALLET_CLIENT_ID="${WALLET_CLIENT_ID:-zorgkantoor-wallet}"

# IMPORTANT: Use USERNAME2 instead of USERNAME
USERNAME2="${USERNAME2:-zorgkantoor-agent}"

# Credential configuration id (Keycloak OID4VC config id)
# If empty, script will auto-pick the first key from well-known
CRED_CONFIG_ID="${CRED_CONFIG_ID:-}"

# Offer-service client (confidential) that is allowed to create credential offers
OFFER_SERVICE_CLIENT_ID='issuer-offer-service'
OFFER_SERVICE_CLIENT_SECRET="${OFFER_SERVICE_CLIENT_SECRET:-}"

# Issuer-service credential endpoint (MUST match aud in proof JWT)
ISSUER_CRED_EP="${ISSUER_CRED_EP:-http://localhost:8081/credential}"

# Optional: wallet endpoints (if your wallet supports them)
# - WALLET_PROOF_EP should return JSON { "proof_jwt": "..." } for given aud+nonce+ccid
# - WALLET_STORE_EP should accept JSON { "format":"jwt_vc", "credential":"..." }
WALLET_PROOF_EP="${WALLET_PROOF_EP:-}"
WALLET_STORE_EP="${WALLET_STORE_EP:-}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }
need curl
need jq

echo "KC_BASE=$KC_BASE"
echo "REALM=$REALM"
echo "WELLKNOWN_EP=$WELLKNOWN_EP"
echo "TOKEN_EP=$TOKEN_EP"
echo "OFFER_HANDLE_EP=$OFFER_HANDLE_EP"
echo "ISSUER_CRED_EP=$ISSUER_CRED_EP"
echo "WALLET_CLIENT_ID=$WALLET_CLIENT_ID"
echo "USERNAME2=$USERNAME2"
echo

############################################
# 1) Discover CRED_CONFIG_ID (optional)
############################################
if [[ -z "${CRED_CONFIG_ID}" ]]; then
  echo "== 1) Discover credential configuration id from well-known =="
  CRED_CONFIG_ID="$(curl -sS "$WELLKNOWN_EP" | jq -r '.credential_configurations_supported | keys[0]')"
  [[ -n "$CRED_CONFIG_ID" && "$CRED_CONFIG_ID" != "null" ]] || { echo "Could not discover CRED_CONFIG_ID"; exit 1; }
fi
echo "CRED_CONFIG_ID=$CRED_CONFIG_ID"
echo

############################################
# 2) Offer-service token (client_credentials)
############################################
echo "== 2) Offer-service token =="
if [[ -z "$OFFER_SERVICE_CLIENT_SECRET" ]]; then
  echo "ERROR: Set OFFER_SERVICE_CLIENT_SECRET env var for client '$OFFER_SERVICE_CLIENT_ID'"
  exit 1
fi


echo "XXXXXXXXXXXXX"
echo "$TOKEN_EP"
echo "$OFFER_SERVICE_CLIENT_ID"
echo "$OFFER_SERVICE_CLIENT_SECRET"
echo "XXXXXXXXXXXXX"

OFFER_TOKEN="$(
  curl -sS -X POST "$TOKEN_EP" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=$OFFER_SERVICE_CLIENT_ID" \
    -d "client_secret=$OFFER_SERVICE_CLIENT_SECRET" \
  | jq -r '.access_token'
)"

[[ -n "$OFFER_TOKEN" && "$OFFER_TOKEN" != "null" ]] || { echo "Failed to obtain OFFER_TOKEN"; exit 1; }
echo "OFFER_TOKEN_LEN=${#OFFER_TOKEN}"
echo

############################################
# 3) Create credential offer handle (nonce)
############################################
echo "== 3) Offer handle =="
OFFER_HANDLE="$(
  curl -sS -G "$OFFER_HANDLE_EP" \
    --data-urlencode "credential_configuration_id=$CRED_CONFIG_ID" \
    --data-urlencode "pre_authorized=true" \
    --data-urlencode "client_id=$WALLET_CLIENT_ID" \
    --data-urlencode "username=$USERNAME2" \
    --data-urlencode "type=uri" \
    -H "Authorization: Bearer $OFFER_TOKEN"
)"
echo "$OFFER_HANDLE" | jq

OFFER_ISSUER="$(echo "$OFFER_HANDLE" | jq -r '.issuer // empty')"
NONCE="$(echo "$OFFER_HANDLE" | jq -r '.nonce // empty')"
[[ -n "$OFFER_ISSUER" && -n "$NONCE" ]] || { echo "Offer handle missing issuer/nonce"; exit 1; }

echo "OFFER_ISSUER=$OFFER_ISSUER"
echo "NONCE=$NONCE"
echo

############################################
# 4) Fetch offer JSON and extract PA_CODE
############################################
echo "== 4) Offer JSON (immediate) =="
OFFER_JSON="$(curl -sS "${OFFER_ISSUER}${NONCE}")"
echo "$OFFER_JSON" | jq

PA_CODE="$(echo "$OFFER_JSON" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] // empty')"
[[ -n "$PA_CODE" && "$PA_CODE" != "null" ]] || { echo "No pre-authorized_code in offer"; exit 1; }
echo "PA_CODE=$PA_CODE"
echo

############################################
# 5) Exchange PA_CODE for ACCESS_TOKEN
############################################
echo "== 5) Wallet token =="
TOKENS="$(
  curl -sS -X POST "$TOKEN_EP" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
    -d "client_id=$WALLET_CLIENT_ID" \
    -d "pre-authorized_code=$PA_CODE"
)"
echo "$TOKENS" | jq '{token_type, expires_in, scope, access_token_len:(.access_token|tostring|length)}'

ACCESS_TOKEN="$(echo "$TOKENS" | jq -r '.access_token // empty')"
[[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]] || { echo "No access_token returned"; exit 1; }
echo "ACCESS_TOKEN_LEN=${#ACCESS_TOKEN}"
echo
echo $ACCESS_TOKEN
echo

############################################
# 6) Probe issuer-service to get c_nonce
############################################
echo "== 6) Probe issuer-service for c_nonce =="
PROBE="$(
  curl -sS -X POST "$ISSUER_CRED_EP" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"credential_configuration_id\":\"$CRED_CONFIG_ID\",\"proof\":{\"proof_type\":\"jwt\",\"jwt\":\"dummy\"}}"
)"
echo "$PROBE" | jq

C_NONCE="$(echo "$PROBE" | jq -r '.c_nonce // empty')"
[[ -n "$C_NONCE" ]] || { echo "No c_nonce from issuer-service"; exit 1; }
echo "C_NONCE=$C_NONCE"
echo

############################################
# 7) Get PROOF_JWT from wallet (required)
############################################
echo "== 7) Get PROOF_JWT from wallet =="

if [[ -z "$WALLET_PROOF_EP" ]]; then
  cat <<EOF
ERROR: WALLET_PROOF_EP not set.

Your wallet must generate PROOF_JWT (it owns the private key).
Set WALLET_PROOF_EP to an endpoint that returns JSON: { "proof_jwt": "<...>" }

Example idea:
  WALLET_PROOF_EP="https://zorgkantoor-wallet.vuggie.net/make-proof"

Then this script will call:
  POST \$WALLET_PROOF_EP
    { "aud":"$ISSUER_CRED_EP", "nonce":"$C_NONCE", "credential_configuration_id":"$CRED_CONFIG_ID" }

EOF
  exit 1
fi

PROOF_REQ="$(jq -nc \
  --arg aud "$ISSUER_CRED_EP" \
  --arg nonce "$C_NONCE" \
  --arg ccid "$CRED_CONFIG_ID" \
  '{aud:$aud, nonce:$nonce, credential_configuration_id:$ccid}')"

PROOF_RESP="$(curl -sS -X POST "$WALLET_PROOF_EP" \
  -H "Content-Type: application/json" \
  -d "$PROOF_REQ")"

PROOF_JWT="$(echo "$PROOF_RESP" | jq -r '.proof_jwt // empty')"
[[ -n "$PROOF_JWT" ]] || { echo "Wallet did not return proof_jwt. Response:"; echo "$PROOF_RESP" | jq; exit 1; }

echo "PROOF_JWT_LEN=${#PROOF_JWT}"
echo

# Extra test: decode PROOF_JWT header to verify it's well-formed (optional)
echo "$PROOF_JWT" | awk -F. '{print $1}' | tr '_-' '/+' | base64 -d 
echo

############################################
# 8) Request credential from issuer-service
############################################


echo "== 8) Request credential =="

HOLDER_KID="${HOLDER_KID:-did:web:zorgkantoor-wallet.vuggie.net#key-1}"

CRED_REQ="$(jq -nc \
  --arg ccid "$CRED_CONFIG_ID" \
  --arg holderKid "$HOLDER_KID" \
  --arg jwt "$PROOF_JWT" \
  '{credential_configuration_id:$ccid, holderKid:$holderKid, proof:{proof_type:"jwt", jwt:$jwt}}')"

CRED_RESP="$(curl -sS -X POST "$ISSUER_CRED_EP" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$CRED_REQ")"

echo "$CRED_RESP" | jq

VC_JWT="$(echo "$CRED_RESP" | jq -r '.credential // empty')"
[[ -n "$VC_JWT" ]] || { echo "No credential returned"; exit 1; }

echo "VC_JWT_LEN=${#VC_JWT}"
echo "VC_JWT=$VC_JWT"
echo

############################################
# 9) Store VC in wallet (optional)
############################################
if [[ -n "$WALLET_STORE_EP" ]]; then
  echo "== 9) Store VC in wallet =="
  STORE_REQ="$(jq -nc --arg fmt "jwt_vc" --arg cred "$VC_JWT" \
    '{format:$fmt, credential:$cred}')"

  STORE_RESP="$(curl -sS -X POST "$WALLET_STORE_EP" \
    -H "Content-Type: application/json" \
    -d "$STORE_REQ")"

  echo "$STORE_RESP" | jq || echo "$STORE_RESP"
  echo "Stored via WALLET_STORE_EP=$WALLET_STORE_EP"
else
  echo "NOTE: WALLET_STORE_EP not set. VC printed above; store it using your wallet's API."
fi
