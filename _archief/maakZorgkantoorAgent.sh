KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
ADMIN_TOKEN=$(./getAdminToken.sh)

curl -sS -X POST "$KC_BASE/admin/realms/$REALM/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "zorgkantoor-agent",
    "enabled": true,
    "emailVerified": true,
    "firstName": "Zorgkantoor",
    "lastName": "Agent"
  }'
echo "created (if 201/204, ok)"
