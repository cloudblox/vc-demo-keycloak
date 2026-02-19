ADMIN_TOKEN=$(./getAdminToken.sh)
REALM="vc-demo"

export SCOPE_NAME="zorgkantoor-jwtvc"

curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/client-scopes/$SCOPE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @- <<JSON
{
  "id": "$SCOPE_ID",
  "name": "zorgkantoor-jwtvc",
  "protocol": "oid4vc",
  "attributes": {
    "include.in.token.scope": "true",
    "vc.credential_configuration_id": "zorgkantoor-jwtvc",
    "vc.verifiable_credential_type": "ZorgkantoorCredential",
    "vc.format": "jwt_vc",
    "vc.credential_signing_alg": "ES256",
    "vc.cryptographic_binding_methods_supported": "jwk",
    "vc.include_in_metadata": "true",
    "vc.display": "[{\"name\":\"Vecozo Zorgkantoor Credential\",\"locale\":\"nl\"}]"
  }
}
JSON
