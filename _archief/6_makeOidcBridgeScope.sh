#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${NEW_REALM:-vc-demo2}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN=$(./getAdminToken.sh)

EXPECTED_SCOPE=$(
  curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-credential-issuer" \
  | jq -r '.credential_configurations_supported["zorgkantoor-jwtvc"].scope'
)

echo "EXPECTED_SCOPE=$EXPECTED_SCOPE"

# does an OIDC scope already exist?
OIDC_ID=$(
  curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r --arg n "$EXPECTED_SCOPE" '.[] | select(.name==$n and .protocol=="openid-connect") | .id' \
  | head -n1
)

if [ -z "$OIDC_ID" ]; then
  # if an oid4vc scope exists with this name, rename it
  OID4VC_ID=$(
    curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" -H "Authorization: Bearer $ADMIN_TOKEN" \
    | jq -r --arg n "$EXPECTED_SCOPE" '.[] | select(.name==$n and .protocol=="oid4vc") | .id' \
    | head -n1
  )
  if [ -n "$OID4VC_ID" ]; then
    NEW_NAME="${EXPECTED_SCOPE}-oid4vc"
    echo "Renaming oid4vc client-scope $OID4VC_ID -> $NEW_NAME"
    curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes/$OID4VC_ID" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
    | jq --arg nn "$NEW_NAME" '.name=$nn' \
    | curl -sS -X PUT "$KC_BASE/admin/realms/$REALM/client-scopes/$OID4VC_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        --data-binary @-
  fi

  echo "Creating OIDC client-scope named $EXPECTED_SCOPE"
  curl -sS -X POST "$KC_BASE/admin/realms/$REALM/client-scopes" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\":\"$EXPECTED_SCOPE\",
      \"protocol\":\"openid-connect\",
      \"attributes\":{ \"include.in.token.scope\":\"true\" }
    }" \
    -w "\nHTTP=%{http_code}\n"

  OIDC_ID=$(
    curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes" -H "Authorization: Bearer $ADMIN_TOKEN" \
    | jq -r --arg n "$EXPECTED_SCOPE" '.[] | select(.name==$n and .protocol=="openid-connect") | .id' \
    | head -n1
  )
fi

echo "OIDC_SCOPE_ID=$OIDC_ID"
