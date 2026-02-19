ADMIN_TOKEN=$(./getAdminToken.sh)
KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"

ROLE_NAME="realm-admin"
RM_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=realm-management" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

ROLES_URL="${KC_BASE}/admin/realms/${REALM}/clients/${RM_ID}/roles"


echo "RM ID $RM_ID"
echo "ROLES URL $ROLES_URL"
