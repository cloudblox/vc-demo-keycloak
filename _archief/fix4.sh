KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
ADMIN_TOKEN=$(./getAdminToken.sh)

curl -sS -X POST "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "zorgkantoor-jwtvc-oidc",
    "protocol": "openid-connect",
    "attributes": {
      "include.in.token.scope": "true"
    }
  }' | cat
echo "created scope zorgkantoor-jwtvc-oidc (if 201/204 ok)"


WALLET_CLIENT_ID="zorgkantoor-wallet"
WALLET_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$WALLET_CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/default-client-scopes/$OIDC_SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

echo "linked zorgkantoor-jwtvc-oidc to zorgkantoor-wallet"
