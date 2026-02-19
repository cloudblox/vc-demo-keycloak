ADMIN_TOKEN=$(./getAdminToken.sh)

KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"

RM_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=realm-management" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

echo "RM ID= ${RM_ID}"

curl -sS "$KC_BASE/admin/realms/$REALM/clients/$RM_ID/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
| jq -r '.[].name' | egrep -i 'offer|credential|oid4vc' || true
