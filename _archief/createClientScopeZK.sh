ADMIN_TOKEN=$(./getAdminToken.sh)
REALM="vc-demo"

export SCOPE_NAME="zorgkantoor-credential"

curl -sS -X POST "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "name": "'"$SCOPE_NAME"'",
    "protocol": "oid4vc",
    "attributes": {
      "include.in.token.scope": "true",

      "vc.format": "jwt_vc",
      "vc.verifiable_credential_type": "https://credentials.vecozo.nl/zorgkantoor",
      "vc.credential_signing_alg": "ES256",
      "vc.display": "[{\"name\":\"Vecozo Zorgkantoor Credential\",\"locale\":\"nl\"}]"
    },
    "protocolMappers": [
      {
        "name": "kvk-mapper",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "kvk",
          "userAttribute": "kvk",
          "vc.display": "[{\"name\":\"KvK\",\"locale\":\"nl\"}]"
        }
      },
      {
        "name": "agb-mapper",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "agb",
          "userAttribute": "agb",
          "vc.display": "[{\"name\":\"AGB\",\"locale\":\"nl\"}]"
        }
      },
      {
        "name": "organisatieNaam-mapper",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "organisatieNaam",
          "userAttribute": "organisatieNaam",
          "vc.display": "[{\"name\":\"Organisatie\",\"locale\":\"nl\"}]"
        }
      },
      {
        "name": "rol-mapper",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "rol",
          "userAttribute": "rol",
          "vc.display": "[{\"name\":\"Rol\",\"locale\":\"nl\"}]"
        }
      },
      {
        "name": "iat-mapper",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-issued-at-time-claim-mapper",
        "config": {
          "claim.name": "iat",
          "truncateToTimeUnit": "HOURS",
          "valueSource": "COMPUTE"
        }
      }
    ]
  }'
