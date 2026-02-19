KC_BASE="https://vecozo-keycloak.vuggie.net"
NEW_REALM="vc-demo2"          
ADMIN_TOKEN=$(./getAdminToken.sh)

curl -sS -X POST "$KC_BASE/admin/realms/$NEW_REALM/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId":"issuer-offer-service",
    "enabled":true,
    "publicClient":false,
    "serviceAccountsEnabled":true,
    "clientAuthenticatorType":"client-secret"
  }' -w "\nHTTP=%{http_code}\n"
