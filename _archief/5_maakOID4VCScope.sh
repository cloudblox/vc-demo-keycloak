KC_BASE="https://vecozo-keycloak.vuggie.net"
NEW_REALM="vc-demo2"          
ADMIN_TOKEN=$(./getAdminToken.sh)

SCOPE_NAME="zorgkantoor-scope"

curl -sS -X POST "$KC_BASE/admin/realms/$NEW_REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"$SCOPE_NAME\",
    \"protocol\":\"oid4vc\",
    \"attributes\":{
      \"include.in.token.scope\":\"true\",
      \"vc.include_in_metadata\":\"true\",
      \"vc.credential_configuration_id\":\"zorgkantoor-jwtvc\",
      \"vc.format\":\"jwt_vc\",
      \"vc.credential_signing_alg\":\"ES256\",
      \"vc.cryptographic_binding_methods_supported\":\"jwk\",
      \"vc.verifiable_credential_type\":\"ZorgkantoorCredential\"
    }
  }" -w "\nHTTP=%{http_code}\n"
