#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN="${ADMIN_TOKEN:-$(./getAdminToken.sh)}"

OFFER_CLIENT_ID="${OFFER_CLIENT_ID:-issuer-offer-service}"
ROLE_NAME="credential-offer-create"

echo "Ensuring realm role exists: $ROLE_NAME"
curl -sS -X POST "$KC_BASE/admin/realms/$REALM/roles"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H "Content-Type: application/json"   -d "{\"name\":\"$ROLE_NAME\"}"   -w "\nHTTP=%{http_code}\n" || true

OFFER_CLIENT_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$OFFER_CLIENT_ID"   -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

SA_USER_ID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients/$OFFER_CLIENT_UUID/service-account-user"   -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.id')

ROLE_JSON=$(curl -sS "$KC_BASE/admin/realms/$REALM/roles/$ROLE_NAME"   -H "Authorization: Bearer $ADMIN_TOKEN")

echo "Mapping role $ROLE_NAME to service-account user of $OFFER_CLIENT_ID"
curl -sS -X POST "$KC_BASE/admin/realms/$REALM/users/$SA_USER_ID/role-mappings/realm"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H "Content-Type: application/json"   -d "[$ROLE_JSON]"   -w "\nHTTP=%{http_code}\n"

echo "Service-account realm roles now:"
curl -sS "$KC_BASE/admin/realms/$REALM/users/$SA_USER_ID/role-mappings/realm"   -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[].name'
