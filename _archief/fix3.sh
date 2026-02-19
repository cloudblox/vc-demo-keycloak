SCOPE_ID="479bbd00-026a-43b9-a1e9-58aa6cb55c9a"
KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
OFFER_CLIENT_ID="issuer-offer-service"
OFFER_CLIENT_SECRET="7ytAIfIbKhUoEja5dNdZGvdRNmhByYqg"
CRED_CONFIG_ID="zorgkantoor-jwtvc"
WALLET_CLIENT_ID="zorgkantoor-wallet"
TARGET_USERNAME="zorgkantoor-agent"
TOKEN_EP="$KC_BASE/realms/$REALM/protocol/openid-connect/token"
ADMIN_TOKEN=$(./getAdminToken.sh)

#curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID" \
#  -H "Authorization: Bearer $ADMIN_TOKEN" \
#| jq '.protocol="openid-connect"' \
#| curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID" \
#    -H "Authorization: Bearer $ADMIN_TOKEN" \
#    -H "Content-Type: application/json" \
#    --data-binary @-

#echo "patched protocol=openid-connect"

# Terug Draaien

SCOPE_ID="479bbd00-026a-43b9-a1e9-58aa6cb55c9a"

curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
| jq '.protocol="oid4vc"' \
| curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @-

echo "protocol reset to oid4vc"
