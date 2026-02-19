#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

CRED_CONFIG_ID="${CRED_CONFIG_ID:-oid4vc_natural_person}"
OFFER_CLIENT_ID="${OFFER_CLIENT_ID:-issuer-offer-service}"
WALLET_CLIENT_ID="${WALLET_CLIENT_ID:-zorgkantoor-wallet}"
TARGET_USERNAME="${TARGET_USERNAME:-zorgkantoor-agent}"

: "${OFFER_CLIENT_SECRET:?Set OFFER_CLIENT_SECRET env var first}"

# 1) Get offer-service token (client_credentials)
OFFER_TOKENS=$(curl -sS -X POST \
  "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OFFER_CLIENT_ID" \
  -d "client_secret=$OFFER_CLIENT_SECRET")

OFFER_TOKEN=$(echo "$OFFER_TOKENS" | jq -r '.access_token // empty')
if [ -z "$OFFER_TOKEN" ]; then
  echo "Failed to get OFFER_TOKEN:" >&2
  echo "$OFFER_TOKENS" | jq >&2
  exit 1
fi

# 2) Get offer handle (issuer + nonce)
HANDLE=$(curl -sS -X GET \
  "$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer-uri?credential_configuration_id=$CRED_CONFIG_ID&pre_authorized=true&client_id=$WALLET_CLIENT_ID&username=$TARGET_USERNAME&type=uri" \
  -H "Authorization: Bearer $OFFER_TOKEN")

ISSUER=$(echo "$HANDLE" | jq -r '.issuer // empty')
NONCE=$(echo "$HANDLE" | jq -r '.nonce // empty')
if [ -z "$ISSUER" ] || [ -z "$NONCE" ]; then
  echo "Offer handle error:" >&2
  echo "$HANDLE" | jq >&2
  exit 1
fi

# 3) Immediately fetch offer JSON (contains pre-authorized_code)
OFFER_JSON=$(curl -sS "${ISSUER}${NONCE}")

PA_CODE=$(echo "$OFFER_JSON" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] // empty')
TX_REQUIRED=$(echo "$OFFER_JSON" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["tx_code"]["input_mode"]? // empty' 2>/dev/null || true)
USER_PIN_REQUIRED=$(echo "$OFFER_JSON" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["user_pin_required"]? // empty' 2>/dev/null || true)

if [ -z "$PA_CODE" ]; then
  echo "No pre-authorized_code in offer JSON:" >&2
  echo "$OFFER_JSON" | jq >&2
  exit 1
fi

echo $PA_CODE
