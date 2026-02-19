KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo}"
ADMIN_TOKEN=$(./getAdminToken.sh)
OID4VC_SCOPE_ID="479bbd00-026a-43b9-a1e9-58aa6cb55c9a"

WALLET_CLIENT_ID="zorgkantoor-wallet"

# wallet client uuid
WALLET_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$WALLET_CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')


echo "xxxxxxxxxxxxxxxxxxxxxxxxxxx"

echo "KC_BASE=[$KC_BASE]"
echo "REALM=[$REALM]"
echo "WALLET_UUID=[$WALLET_UUID]"
echo "OID4VC_SCOPE_ID=[$OID4VC_SCOPE_ID]"


echo "xxxxxxxxxxxxxxxxxxxxxxxxxxx"


# verwijderen uit DEFAULT
curl -sS -X DELETE \
  "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/default-client-scopes/$OID4VC_SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
