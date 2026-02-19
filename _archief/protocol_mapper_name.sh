REALM="vc-demo"
KC_BASE="https://vecozo-keycloak.vuggie.net"
TOKEN=$(./getAdminToken.sh)
sleep 3
SCOPE_ID=$(curl -s "$KC_BASE/admin/realms/$REALM/client-scopes" -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.name=="membership-credential") | .id')

echo $SCOPE_ID




exit 0

curl -s -X POST "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "given_name",
    "protocol": "oid4vc",
    "protocolMapper": "oid4vc-user-attribute-mapper",
    "config": {
      "claim.name": "given_name",
      "userAttribute": "firstName",
      "vc.display": "[{\"name\":\"Given name\",\"locale\":\"en\"}]"
    }
  }' | jq .
