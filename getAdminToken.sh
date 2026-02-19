export KC_BASE="https://vecozo-keycloak.vuggie.net"
export ADMIN_REALM="master"
export ADMIN_USER="admin"
export ADMIN_PASS="FdE1YRL3569X"
export ADMIN_CLIENT="admin-cli"

ADMIN_TOKEN=$(curl -s \
  -d "grant_type=password" \
  -d "client_id=$ADMIN_CLIENT" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" \
  "$KC_BASE/realms/$ADMIN_REALM/protocol/openid-connect/token" \
  | jq -r .access_token)


echo $ADMIN_TOKEN
