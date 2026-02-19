KC_BASE="https://vecozo-keycloak.vuggie.net"
NEW_REALM="vc-demo2"          
ADMIN_TOKEN=$(./getAdminToken.sh)


curl -sS -X POST "$KC_BASE/admin/realms/$NEW_REALM/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId":"zorgkantoor-wallet",
    "enabled":true,
    "publicClient":true,
    "standardFlowEnabled":true,
    "directAccessGrantsEnabled":false,
    "redirectUris":["https://zorgkantoor-wallet.vuggie.net/callback"],
    "webOrigins":["https://zorgkantoor-wallet.vuggie.net"]
  }' -w "\nHTTP=%{http_code}\n"
