REALM="vc-demo"
KC_BASE="https://vecozo-keycloak.vuggie.net"

OIDC_JSON="$(curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-configuration")"
AUTHZ_ENDPOINT="$(echo "$OIDC_JSON" | jq -r .authorization_endpoint)"
TOKEN_ENDPOINT="$(echo "$OIDC_JSON" | jq -r .token_endpoint)"

echo "AUTHZ_ENDPOINT=$AUTHZ_ENDPOINT"
echo "TOKEN_ENDPOINT=$TOKEN_ENDPOINT"
