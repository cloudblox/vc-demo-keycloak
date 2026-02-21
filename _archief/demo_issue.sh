#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

: "${OFFER_CLIENT_SECRET:?Set OFFER_CLIENT_SECRET env var first}"

CRED_CONFIG_ID="${CRED_CONFIG_ID:-oid4vc_natural_person}"
OFFER_CLIENT_ID="${OFFER_CLIENT_ID:-issuer-offer-service}"
WALLET_CLIENT_ID="${WALLET_CLIENT_ID:-zorgkantoor-wallet}"
TARGET_USERNAME="${TARGET_USERNAME:-zorgkantoor-agent}"
ISSUER_SVC_CRED_EP="${ISSUER_SVC_CRED_EP:-http://localhost:8081/credential}"
ISSUER_AUD="${ISSUER_AUD:-issuer-service}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }
need curl; need jq; need node; need npm

# ensure jose for proof JWT generation
if [ ! -d node_modules/jose ]; then
  npm i jose >/dev/null
fi

echo "== 1) Offer-service token =="
OFFER_TOKENS=$(curl -sS -X POST \
  "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OFFER_CLIENT_ID" \
  -d "client_secret=$OFFER_CLIENT_SECRET")

OFFER_TOKEN=$(echo "$OFFER_TOKENS" | jq -r '.access_token // empty')
[ -n "$OFFER_TOKEN" ] || { echo "$OFFER_TOKENS" | jq; exit 1; }

echo "== 2) Offer handle =="
HANDLE=$(curl -sS -X GET \
  "$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer-uri?credential_configuration_id=$CRED_CONFIG_ID&pre_authorized=true&client_id=$WALLET_CLIENT_ID&username=$TARGET_USERNAME&type=uri" \
  -H "Authorization: Bearer $OFFER_TOKEN")

echo "$HANDLE" | jq
ISSUER=$(echo "$HANDLE" | jq -r '.issuer // empty')
NONCE=$(echo "$HANDLE" | jq -r '.nonce // empty')
[ -n "$ISSUER" ] && [ -n "$NONCE" ] || { echo "Bad handle"; exit 1; }

echo "== 3) Offer JSON (immediate) =="
OFFER_JSON=$(curl -sS "${ISSUER}${NONCE}")
echo "$OFFER_JSON" | jq

PA_CODE=$(echo "$OFFER_JSON" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] // empty')
[ -n "$PA_CODE" ] || { echo "No pre-authorized_code"; exit 1; }
echo "PA_CODE=$PA_CODE"

echo "== 4) Wallet token =="
TOK=$(curl -sS -X POST \
  "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  -d "client_id=$WALLET_CLIENT_ID" \
  -d "pre-authorized_code=$PA_CODE")

# if error, print full
AT_LEN=$(echo "$TOK" | jq -r '(.access_token|tostring|length) // 0' 2>/dev/null || echo 0)
if [ "$AT_LEN" -lt 200 ]; then
  echo "$TOK" | jq
  echo "Wallet token did not return access_token. Above is the error."
  exit 1
fi

ACCESS_TOKEN=$(echo "$TOK" | jq -r '.access_token' | tr -d '\r\n')
echo "ACCESS_TOKEN_LEN=${#ACCESS_TOKEN}"

echo "== 5) Probe issuer-service for c_nonce =="
PROBE=$(curl -sS -X POST "$ISSUER_SVC_CRED_EP" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"credential_configuration_id\":\"$CRED_CONFIG_ID\",\"proof\":{\"proof_type\":\"jwt\",\"jwt\":\"dummy\"}}")

echo "$PROBE" | jq
C_NONCE=$(echo "$PROBE" | jq -r '.c_nonce // empty')
[ -n "$C_NONCE" ] || { echo "No c_nonce from issuer-service"; exit 1; }
echo "C_NONCE=$C_NONCE"

echo "== 6) Create holder proof JWT =="
PROOF_JWT="$(C_NONCE="$C_NONCE" ISSUER_AUD="$ISSUER_AUD" node - <<'NODE'
import { generateKeyPair, exportJWK, SignJWT } from "jose";
const nonce = process.env.C_NONCE;
const aud = process.env.ISSUER_AUD || "issuer-service";
const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
const jwkPub = await exportJWK(publicKey);
const now = Math.floor(Date.now()/1000);
const jwt = await new SignJWT({ nonce })
  .setProtectedHeader({ alg: "ES256", typ: "JWT", jwk: jwkPub })
  .setIssuedAt(now)
  .setAudience(aud)
  .setExpirationTime(now + 300)
  .sign(privateKey);
process.stdout.write(jwt);
NODE
)"
echo "PROOF_JWT_LEN=${#PROOF_JWT}"

echo "== 7) Request credential =="
BODY=$(jq -nc --arg ccid "$CRED_CONFIG_ID" --arg jwt "$PROOF_JWT" \
  '{credential_configuration_id:$ccid, proof:{proof_type:"jwt", jwt:$jwt}}')

RESP=$(curl -sS -X POST "$ISSUER_SVC_CRED_EP" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$BODY")

echo "$RESP" | jq

JWT_VC=$(echo "$RESP" | jq -r '.credential // empty')
[ -n "$JWT_VC" ] || { echo "No credential returned"; exit 1; }

echo
echo "JWT_VC_LEN=${#JWT_VC}"
echo "JWT_VC=$JWT_VC"
