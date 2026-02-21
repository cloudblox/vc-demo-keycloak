REALM="vc-demo"
ADMIN_TOKEN=$(./getAdminToken.sh)

curl -X POST "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "membership-credential",
    "protocol": "oid4vc",
    "attributes": {
      "vc.format": "dc+sd-jwt",
      "vc.verifiable_credential_type": "https://example.org/credentials/membership",
      "vc.credential_signing_alg": "ES256"
    }
  }'
