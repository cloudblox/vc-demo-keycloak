ADMIN_TOKEN=$(./getAdminToken.sh)
SCOPE_ID="479bbd00-026a-43b9-a1e9-58aa6cb55c9a"

curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
| jq '.attributes["include.in.token.scope"]="true"' \
| curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @-

echo "patched include.in.token.scope=true"
