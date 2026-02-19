#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${NEW_REALM:-vc-demo2}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN=$(./getAdminToken.sh)

EXPECTED_SCOPE=$(
  curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-credential-issuer" \
  | jq -r '.credential_configurations_supported["zorgkantoor-jwtvc"].scope'
)

OIDC_SCOPE_ID=$(
  curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r --arg n "$EXPECTED_SCOPE" '.[] | select(.name==$n and .protocol=="openid-connect") | .id' \
  | head -n1
)

WALLET_UUID=$(
  curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=zorgkantoor-wallet" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r '.[0].id'
)

echo "EXPECTED_SCOPE=$EXPECTED_SCOPE"
echo "OIDC_SCOPE_ID=$OIDC_SCOPE_ID"
echo "WALLET_UUID=$WALLET_UUID"

curl -sS -X PUT \
  "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/default-client-scopes/$OIDC_SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -w "\nHTTP=%{http_code}\n"
