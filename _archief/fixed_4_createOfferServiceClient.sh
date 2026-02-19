#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN="${ADMIN_TOKEN:-$(./getAdminToken.sh)}"

OFFER_CLIENT_ID="${OFFER_CLIENT_ID:-issuer-offer-service}"

echo "Creating offer-service client: $OFFER_CLIENT_ID"
curl -sS -X POST "$KC_BASE/admin/realms/$REALM/clients"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H "Content-Type: application/json"   -d "{
    \"clientId\":\"$OFFER_CLIENT_ID\",
    \"enabled\":true,
    \"publicClient\":false,
    \"serviceAccountsEnabled\":true,
    \"clientAuthenticatorType\":\"client-secret\"
  }"   -w "\nHTTP=%{http_code}\n"

echo
echo "MANUAL (one-time): enable OID4VCI for $OFFER_CLIENT_ID:"
echo "Clients -> $OFFER_CLIENT_ID -> Advanced -> OpenID for Verifiable Credentials -> Enable OID4VCI"
