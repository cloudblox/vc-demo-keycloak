ADMIN_TOKEN=$(./getAdminToken.sh)
export KC_BASE="https://vecozo-keycloak.vuggie.net"
export REALM="vc-demo"


SCOPE_ID=$(                                         
  curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.name=="'"$SCOPE_NAME"'") | .id')
echo "SCOPE_ID=$SCOPE_ID"


add_mapper () {
  local NAME="$1" USER_ATTR="$2" CLAIM="$3"
  curl -sS -X POST "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"$NAME\",
      \"protocol\": \"openid-connect\",
      \"protocolMapper\": \"oidc-usermodel-attribute-mapper\",
      \"consentRequired\": false,
      \"config\": {
        \"user.attribute\": \"$USER_ATTR\",
        \"claim.name\": \"$CLAIM\",
        \"jsonType.label\": \"String\",
        \"id.token.claim\": \"false\",
        \"access.token.claim\": \"false\",
        \"userinfo.token.claim\": \"true\"
      }
    }" >/dev/null
}

add_mapper "kvk" "kvk" "kvk"
add_mapper "agb" "agb" "agb"
add_mapper "organisatieNaam" "organisatieNaam" "organisatieNaam"
add_mapper "rol" "rol" "rol"

echo "mappers added to scope $SCOPE_ID"
