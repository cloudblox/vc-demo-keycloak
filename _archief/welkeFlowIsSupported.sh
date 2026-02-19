REALM="vc-demo"
KC_BASE="https://vecozo-keycloak.vuggie.net"

curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-credential-issuer" \
| jq '{credential_endpoint, token_endpoint, grants, credential_configurations_supported}'
