#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN="${ADMIN_TOKEN:-$(./getAdminToken.sh)}"

SCOPE_NAME="${SCOPE_NAME:-zk-vc}"
CRED_CONFIG_ID="${CRED_CONFIG_ID:-zorgkantoor-jwtvc}"
WALLET_CLIENT_ID="${WALLET_CLIENT_ID:-zorgkantoor-wallet}"

echo "Creating VC client-scope (protocol=openid-connect) name=$SCOPE_NAME"
curl -sS -X POST "$KC_BASE/admin/realms/$REALM/client-scopes"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H "Content-Type: application/json"   -d "{
    \"name\":\"$SCOPE_NAME\",
    \"protocol\":\"openid-connect\",
    \"attributes\": {
      \"include.in.token.scope\":\"true\",
      \"vc.include_in_metadata\":\"true\",
      \"vc.credential_configuration_id\":\"$CRED_CONFIG_ID\",
      \"vc.credential_identifier\":\"$SCOPE_NAME\",
      \"vc.supported_credential_types\":\"$SCOPE_NAME\",
      \"vc.credential_contexts\":\"$SCOPE_NAME\",
      \"vc.format\":\"jwt_vc\",
      \"vc.credential_signing_alg\":\"ES256\",
      \"vc.cryptographic_binding_methods_supported\":\"jwk\",
      \"vc.expiry_in_seconds\":\"31536000\"
    }
  }"   -w "\nHTTP=%{http_code}\n"

SCOPE_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/client-scopes"   -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r --arg n "$SCOPE_NAME" '.[] | select(.name==$n) | .id' | head -n1)

if [ -z "$SCOPE_ID" ] || [ "$SCOPE_ID" = "null" ]; then
  echo "ERROR: could not resolve scope id for $SCOPE_NAME" >&2
  exit 1
fi

WALLET_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$WALLET_CLIENT_ID"   -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

echo "Linking scope $SCOPE_NAME ($SCOPE_ID) as default for wallet $WALLET_CLIENT_ID ($WALLET_UUID)"
curl -sS -X PUT   "$KC_BASE/admin/realms/$REALM/clients/$WALLET_UUID/default-client-scopes/$SCOPE_ID"   -H "Authorization: Bearer $ADMIN_TOKEN"   -w "\nHTTP=%{http_code}\n"

echo
echo "Check .well-known:"
curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-credential-issuer" | jq --arg id "$CRED_CONFIG_ID" '.credential_configurations_supported[$id] | {id, scope, format}'
