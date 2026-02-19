KC_BASE="https://vecozo-keycloak.vuggie.net"
NEW_REALM="vc-demo2"          
ADMIN_TOKEN=$(./getAdminToken.sh)

curl -sS -X POST "$KC_BASE/admin/realms/$NEW_REALM/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"zorgkantoor-agent",
    "enabled":true,
    "firstName":"Zorgkantoor",
    "lastName":"Agent",
    "email":"zorgkantoor-agent@example.org",
    "emailVerified":true
  }' -w "\nHTTP=%{http_code}\n"
