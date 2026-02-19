KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo2"   # belangrijk: dezelfde realm als waar 6 draaide
ADMIN_TOKEN=$(./getAdminToken.sh)

WALLET_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=zorgkantoor-wallet" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

echo "WALLET_UUID $WALLET_UUID"

OIDC_SCOPE_ID="1a8236b0-523a-4d98-8e1a-f2dd354ba9a3"

echo "REALM=$REALM"
echo "WALLET_UUID=$WALLET_UUID"
echo "OIDC_SCOPE_ID=$OIDC_SCOPE_ID"

curl -sS -X PUT \
  "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/default-client-scopes/$OIDC_SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -w "\nHTTP=%{http_code}\n"
