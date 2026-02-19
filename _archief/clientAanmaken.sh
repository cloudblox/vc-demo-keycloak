ADMIN_TOKEN=$(./getAdminToken.sh)
KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
CLIENT_ID="zorgkantoor-wallet"

curl -sS -X POST "$KC_BASE/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @- <<JSON
{
  "clientId": "zorgkantoor-wallet",
  "name": "Zorgkantoor Wallet",
  "protocol": "openid-connect",
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "implicitFlowEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": [
    "http://localhost:8080/*"
  ],
  "webOrigins": [
    "http://localhost:8080"
  ]
}
JSON

echo "Created client: $CLIEND_ID"


CLIENT_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
| jq -r '.[0].id')

echo $CLIENT_UUID


echo "Koppelen van de Scope"

SCOPE_NAME="zorgkantoor-jwtvc"

SCOPE_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
| jq -r ".[] | select(.name==\"$SCOPE_NAME\") | .id")

curl -sS -X PUT \
  "$KC_BASE/admin/realms/$REALM/clients/$CLIENT_UUID/default-client-scopes/$SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
