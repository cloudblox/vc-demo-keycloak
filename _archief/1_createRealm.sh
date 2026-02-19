KC_BASE="https://vecozo-keycloak.vuggie.net"
NEW_REALM="vc-demo2"          # kies nieuwe realm naam
ADMIN_TOKEN=$(./getAdminToken.sh)
KC_BASE="${KC_BASE%/}"
ADMIN_TOKEN=$(./getAdminToken.sh)


curl -sS -X POST "$KC_BASE/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"realm\":\"$NEW_REALM\",\"enabled\":true}" \
  -w "\nHTTP=%{http_code}\n"
