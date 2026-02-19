#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN="${ADMIN_TOKEN:-$(./getAdminToken.sh)}"

OFFER_CLIENT_ID="${OFFER_CLIENT_ID:-issuer-offer-service}"

OFFER_CLIENT_UUID=$(curl -sS "$KC_BASE/admin/realms/$REALM/clients?clientId=$OFFER_CLIENT_ID"   -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

echo "Offer service client UUID: $OFFER_CLIENT_UUID"
echo "Client secret:"
curl -sS "$KC_BASE/admin/realms/$REALM/clients/$OFFER_CLIENT_UUID/client-secret"   -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.value'
