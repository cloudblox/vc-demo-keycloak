#!/usr/bin/env bash
set -euo pipefail
CRED_CONFIG_ID="zorgkantoor-jwtvc"
WALLET_SCOPE="zorgkantoor-jwtvc-oid4vc-oid4vc"

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo}"

# Offer service client (client_credentials) -> used to create credential offer
OFFER_CLIENT_ID="${OFFER_CLIENT_ID:-issuer-offer-service}"
: "${OFFER_CLIENT_SECRET:?Set OFFER_CLIENT_SECRET env var (do not hardcode)}"

# Wallet client id + user to issue to
WALLET_CLIENT_ID="${WALLET_CLIENT_ID:-zorgkantoor-wallet}"
TARGET_USERNAME="${TARGET_USERNAME:-zorgkantoor-agent}"


KC_BASE="${KC_BASE%/}"
TOKEN_EP="$KC_BASE/realms/$REALM/protocol/openid-connect/token"
OFFER_URI_EP="$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer-uri"
OFFER_EP="$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer"
CRED_EP="$(curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-credential-issuer" | jq -r '.credential_endpoint')"

echo "KC_BASE=$KC_BASE"
echo "REALM=$REALM"
echo "CRED_EP=$CRED_EP"
echo "CRED_CONFIG_ID=$CRED_CONFIG_ID"
echo "WALLET_CLIENT_ID=$WALLET_CLIENT_ID"
echo "TARGET_USERNAME=$TARGET_USERNAME"
echo

########################################
# 1) Get OFFER_TOKEN (client_credentials)
########################################
OFFER_TOKENS="$(curl -sS -X POST "$TOKEN_EP" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OFFER_CLIENT_ID" \
  -d "client_secret=$OFFER_CLIENT_SECRET")"

OFFER_TOKEN="$(echo "$OFFER_TOKENS" | jq -r '.access_token')"
if [ -z "${OFFER_TOKEN:-}" ] || [ "$OFFER_TOKEN" = "null" ]; then
  echo "Failed to obtain OFFER_TOKEN:" >&2
  echo "$OFFER_TOKENS" | jq >&2 || echo "$OFFER_TOKENS" >&2
  exit 1
fi
echo "OFFER_TOKEN_LEN=${#OFFER_TOKEN}"
echo

########################################
# 2) Create offer handle + immediately fetch offer JSON (avoid expiry)
########################################
RESP="$(curl -sS -X GET \
  "$OFFER_URI_EP?credential_configuration_id=$CRED_CONFIG_ID&pre_authorized=true&client_id=$WALLET_CLIENT_ID&username=$TARGET_USERNAME&type=uri" \
  -H "Authorization: Bearer $OFFER_TOKEN")"

echo "Offer handle:"
echo "$RESP" | jq

OFFER_NONCE="$(echo "$RESP" | jq -r '.nonce // empty')"
if [ -z "$OFFER_NONCE" ]; then
  echo "Offer handle did not return nonce (offer creation failed)." >&2
  exit 1
fi

OFFER_JSON="$(curl -sS -X GET \
  "$OFFER_EP/$OFFER_NONCE" \
  -H "Authorization: Bearer $OFFER_TOKEN")"

echo
echo "Offer JSON:"
echo "$OFFER_JSON" | jq

PA_CODE="$(echo "$OFFER_JSON" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] // empty')"
if [ -z "$PA_CODE" ]; then
  echo "No pre-authorized_code found in offer JSON." >&2
  exit 1
fi

TX_REQUIRED="$(echo "$OFFER_JSON" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["tx_code_required"] // false')"

echo
echo "PA_CODE=$PA_CODE"
echo "TX_REQUIRED=$TX_REQUIRED"
echo

########################################
# 3) Wallet access token (pre-authorized_code) - OIDC scopes ONLY
#    IMPORTANT: do NOT request zorgkantoor-jwtvc-oid4vc here.
########################################

TOKENS="$(curl -sS -X POST "$TOKEN_EP" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  -d "pre-authorized_code=$PA_CODE" \
  -d "client_id=$WALLET_CLIENT_ID" \
  -d "scope=$WALLET_SCOPE"
)"

echo "Wallet token response:"
echo "$TOKENS" | jq

ACCESS_TOKEN="$(echo "$TOKENS" | jq -r '.access_token // empty')"
if [ -z "$ACCESS_TOKEN" ]; then
  echo "No access_token in wallet token response." >&2
  exit 1
fi

echo "ACCESS_TOKEN_LEN=${#ACCESS_TOKEN}"

# Debug: show token scope claim and fail fast if oid4vc scope leaks in
TOKEN_SCOPE=$(
  echo "$ACCESS_TOKEN" | cut -d. -f2 \
  | tr '_-' '/+' \
  | awk '{print $0 "==="}' \
  | base64 -d 2>/dev/null \
  | jq -r '.scope' || true
)
echo "TOKEN_SCOPE=[$TOKEN_SCOPE]"

########################################
# 4) Probe to get c_nonce
########################################
PROBE="$(curl -sS -X POST "$CRED_EP" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"credential_configuration_id\": \"$CRED_CONFIG_ID\",
    \"proof\": { \"proof_type\": \"jwt\", \"jwt\": \"dummy\" }
  }")"

echo "Probe response:"
echo "$PROBE" | jq

C_NONCE="$(echo "$PROBE" | jq -r '.c_nonce // empty')"
if [ -z "$C_NONCE" ]; then
  echo
  echo "No c_nonce returned. If error above is invalid_proof without c_nonce, paste it here." >&2
  exit 1
fi
echo "C_NONCE=$C_NONCE"
echo

########################################
# 5) Create proof JWT + request credential
########################################
command -v node >/dev/null || { echo "node not found. Install node to create ES256 proof JWT."; exit 1; }

if [ ! -d node_modules/jose ]; then
  echo "Installing jose (local)..."
  npm i jose >/dev/null
fi

export CRED_EP
export C_NONCE

PROOF_JWT="$(node - <<'NODE'
import fs from "fs";
import { SignJWT, generateKeyPair, exportJWK, importJWK } from "jose";

const aud = process.env.CRED_EP;
const nonce = process.env.C_NONCE;

const privPath = ".holder_private.jwk";
const pubPath  = ".holder_public.jwk";

let privJwk;
if (fs.existsSync(privPath)) {
  privJwk = JSON.parse(fs.readFileSync(privPath, "utf8"));
} else {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const pub = await exportJWK(publicKey);
  privJwk = await exportJWK(privateKey);
  const kid = "holder-key-1";
  pub.kid = kid; privJwk.kid = kid;
  fs.writeFileSync(pubPath, JSON.stringify(pub, null, 2));
  fs.writeFileSync(privPath, JSON.stringify(privJwk, null, 2));
}

const key = await importJWK(privJwk, "ES256");

const jwt = await new SignJWT({ nonce })
  .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: privJwk.kid })
  .setIssuer("holder")
  .setAudience(aud)
  .setIssuedAt()
  .sign(key);

process.stdout.write(jwt);
NODE
)"

echo "PROOF_JWT_LEN=${#PROOF_JWT}"

VC_RESP="$(curl -sS -X POST "$CRED_EP" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"credential_configuration_id\": \"$CRED_CONFIG_ID\",
    \"proof\": { \"proof_type\": \"jwt\", \"jwt\": \"$PROOF_JWT\" }
  }")"

echo
echo "Credential response:"
echo "$VC_RESP" | jq
