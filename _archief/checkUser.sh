ADMIN_TOKEN=$(./getAdminToken.sh)
KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
USERNAME="vecozo-offerbot"

USER_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/users?username=$USERNAME" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

RM_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=realm-management" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

echo "USER_ID=$USER_ID"
echo "RM_ID=$RM_ID"

curl -sS "$KC_BASE/admin/realms/$REALM/users/$USER_ID/role-mappings/clients/$RM_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[].name'

