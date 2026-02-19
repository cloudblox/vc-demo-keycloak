KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
ADMIN_TOKEN=$(./getAdminToken.sh)

WALLET_CLIENT_ID="zorgkantoor-wallet"

# wallet client uuid
WALLET_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$WALLET_CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

# scope id (zorgkantoor-jwtvc)
SCOPE_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
| jq -r '.[] | select(.name=="zorgkantoor-jwtvc") | .id')

echo "WALLET_UUID=$WALLET_UUID"
echo "SCOPE_ID=$SCOPE_ID"

# koppel als OPTIONAL (aanrader)
curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/optional-client-scopes/$SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
echo "linked as optional"


curl -sS "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/optional-client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[].name'
