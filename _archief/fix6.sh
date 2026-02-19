KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
ADMIN_TOKEN=$(./getAdminToken.sh)
REALM="vc-demo"

curl -sS -X POST "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "zorgkantoor-jwtvc",
    "protocol": "openid-connect",
    "attributes": {
      "include.in.token.scope": "true"
    }
  }' | cat

OIDC_SCOPE_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
| jq -r '.[] | select(.name=="zorgkantoor-jwtvc" and .protocol=="openid-connect") | .id')

echo "OIDC_SCOPE_ID=$OIDC_SCOPE_ID"

# Stap 3 — Koppel die scope als default aan zorgkantoor-wallet

WALLET_CLIENT_ID="zorgkantoor-wallet"

WALLET_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$WALLET_CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/default-client-scopes/$OIDC_SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

echo "linked zorgkantoor-jwtvc (openid-connect) to wallet defaults"
