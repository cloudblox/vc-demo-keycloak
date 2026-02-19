#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# fixed_getToken.sh
# End-to-end (Keycloak-only) demo:
#  1) Offer-service gets client_credentials token
#  2) Create credential offer handle (nonce)
#  3) Fetch offer JSON, extract pre-authorized_code
#  4) Wallet exchanges pre-authorized_code for access_token (using scope from metadata)
#  5) Probe credential endpoint to obtain c_nonce
#  6) Create holder proof JWT (ES256, ephemeral key) and request credential
#
# Requirements: curl jq node npm
# -----------------------------------------------------------------------------

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

WALLET_CLIENT_ID="${WALLET_CLIENT_ID:-zorgkantoor-wallet}"
OFFER_CLIENT_ID="${OFFER_CLIENT_ID:-issuer-offer-service}"
TARGET_USERNAME="${TARGET_USERNAME:-zorgkantoor-agent}"

# This is the credential_configuration_id as shown under
# /.well-known/openid-credential-issuer -> credential_configurations_supported
CRED_CONFIG_ID="zorgkantoor-jwtvc"

# Optional extra OIDC scopes to request alongside the OID4VCI scope (not required)
EXTRA_OIDC_SCOPES="${EXTRA_OIDC_SCOPES:-email profile}"

OFFER_CLIENT_SECRET="${OFFER_CLIENT_SECRET:-}"
if [ -z "$OFFER_CLIENT_SECRET" ]; then
  echo "ERROR: set OFFER_CLIENT_SECRET (secret for $OFFER_CLIENT_ID)." >&2
  echo "Tip: run your script that prints the offer-service client secret." >&2
  exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing dependency: $1" >&2; exit 1; }; }
need curl
need jq

CRED_EP="$KC_BASE/realms/$REALM/protocol/oid4vc/credential"

echo "KC_BASE=$KC_BASE"
echo "REALM=$REALM"
echo "CRED_EP=$CRED_EP"
echo "CRED_CONFIG_ID=$CRED_CONFIG_ID"
echo

########################################
# 0) Resolve wallet scope from metadata
########################################
WALLET_SCOPE="$(curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-credential-issuer" \
  | jq -r --arg id "$CRED_CONFIG_ID" '.credential_configurations_supported[$id].scope // empty')"

if [ -z "$WALLET_SCOPE" ]; then
  echo "ERROR: could not determine scope for credential_configuration_id=$CRED_CONFIG_ID from .well-known." >&2
  echo "Check: curl -sS \"$KC_BASE/realms/$REALM/.well-known/openid-credential-issuer\" | jq '.credential_configurations_supported|keys'" >&2
  exit 1
fi

echo "WALLET_SCOPE(from metadata)=$WALLET_SCOPE"
echo

########################################
# 1) Offer-service token (client_credentials)
########################################
OFFER_TOKENS="$(curl -sS -X POST "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OFFER_CLIENT_ID" \
  -d "client_secret=$OFFER_CLIENT_SECRET")"

OFFER_TOKEN="$(echo "$OFFER_TOKENS" | jq -r '.access_token // empty')"
echo "OFFER_TOKEN_LEN=${#OFFER_TOKEN}"
echo

if [ -z "$OFFER_TOKEN" ]; then
  echo "ERROR: offer-service token response missing access_token" >&2
  echo "$OFFER_TOKENS" | jq >&2 || true
  exit 1
fi

########################################
# 2) Offer handle (nonce)
########################################
OFFER_HANDLE="$(curl -sS -X GET \
  "$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer-uri?credential_configuration_id=$CRED_CONFIG_ID&pre_authorized=true&client_id=$WALLET_CLIENT_ID&username=$TARGET_USERNAME&type=uri" \
  -H "Authorization: Bearer $OFFER_TOKEN")"

echo "Offer handle:"
echo "$OFFER_HANDLE" | jq
echo

NONCE="$(echo "$OFFER_HANDLE" | jq -r '.nonce // empty')"
OFFER_ISSUER="$(echo "$OFFER_HANDLE" | jq -r '.issuer // empty')"

if [ -z "$NONCE" ] || [ -z "$OFFER_ISSUER" ]; then
  echo "ERROR: Offer handle did not return issuer+nonce." >&2
  exit 1
fi

# Use issuer from handle to avoid path mismatches
OFFER_JSON="$(curl -sS "${OFFER_ISSUER}${NONCE}")"

echo "Offer JSON:"
echo "$OFFER_JSON" | jq
echo

PA_CODE="$(echo "$OFFER_JSON" \
  | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] // empty')"

if [ -z "$PA_CODE" ]; then
  echo "ERROR: No pre-authorized_code in offer JSON." >&2
  exit 1
fi

echo "PA_CODE=$PA_CODE"
echo

########################################
# 3) Wallet token (pre-authorized_code)
########################################
# Build scope string: "<wallet_scope> [extra...]"
SCOPE_STR="$WALLET_SCOPE"
# Append extras if not already present
for s in $EXTRA_OIDC_SCOPES; do
  if ! echo " $SCOPE_STR " | grep -q " $s "; then
    SCOPE_STR="$SCOPE_STR $s"
  fi
done

TOKENS="$(curl -sS -X POST "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  -d "pre-authorized_code=$PA_CODE" \
  -d "client_id=$WALLET_CLIENT_ID" \
  -d "scope=$SCOPE_STR")"

echo "Wallet token response:"
echo "$TOKENS" | jq

echo "XXXXXX"
echo "$TOKENS" | jq -r '.scope'
echo "XXXXXX"
ACCESS_TOKEN="$(echo "$TOKENS" | jq -r '.access_token // empty')"
echo "ACCESS_TOKEN_LEN=${#ACCESS_TOKEN}"
echo

if [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: wallet token response missing access_token" >&2
  exit 1
fi

########################################
# 4) Probe to get c_nonce (expect invalid_proof + c_nonce)
########################################


DUMMY_JWT='eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.'

PROBE_BODY=$(jq -nc --arg ccid "$CRED_CONFIG_ID" --arg jwt "$DUMMY_JWT" \
  '{credential_configuration_id:$ccid, proof:{proof_type:"jwt", jwt:$jwt}}')

PROBE=$(curl -sS -w "\nHTTP=%{http_code}\n" -X POST "$CRED_EP" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$PROBE_BODY")

echo "$PROBE" | head -n 200

C_NONCE="$(echo "$PROBE" | jq -r '.c_nonce // empty')"
if [ -z "$C_NONCE" ]; then
  echo "No c_nonce returned. If error above is invalid_proof without c_nonce, paste it here." >&2
  exit 1
fi

echo "C_NONCE=$C_NONCE"
echo

########################################
# 5) Create proof JWT + request credential
########################################
need node
need npm

# Ensure jose is available locally (installs in current folder)
if [ ! -d node_modules/jose ]; then
  echo "Installing jose (local)..."
  npm i jose >/dev/null
fi

export C_NONCE CRED_CONFIG_ID

PROOF_JWT="$(node - <<'NODE'
const { SignJWT, generateKeyPair, exportJWK } = require('jose');

(async () => {
  // Ephemeral holder key pair (ES256). Public JWK is embedded as cnf in the VC by Keycloak.
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  jwk.use = 'sig';
  jwk.alg = 'ES256';

  const now = Math.floor(Date.now() / 1000);
  const jwt = await new SignJWT({
    nonce: process.env.C_NONCE
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', jwk })
    // Keycloak expects this audience for proof in OID4VCI
    .setAudience(process.env.CRED_CONFIG_ID)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);

  process.stdout.write(jwt);
})().catch(e => { console.error(e); process.exit(1); });
NODE
)"

echo "PROOF_JWT_LEN=${#PROOF_JWT}"
echo

BODY="$(jq -nc --arg ccid "$CRED_CONFIG_ID" --arg jwt "$PROOF_JWT" \
  '{credential_configuration_id:$ccid, proof:{proof_type:"jwt", jwt:$jwt}}')"

RESP="$(curl -sS -X POST "$CRED_EP" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$BODY")"

echo "Credential response:"
echo "$RESP" | jq
echo

JWT_VC="$(echo "$RESP" | jq -r '.credential // empty')"
if [ -z "$JWT_VC" ]; then
  echo "ERROR: No .credential returned." >&2
  exit 1
fi

echo "JWT_VC_LEN=${#JWT_VC}"
echo "JWT_VC=$JWT_VC"
