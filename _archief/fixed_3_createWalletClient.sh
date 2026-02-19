#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN="${ADMIN_TOKEN:-$(./getAdminToken.sh)}"

WALLET_CLIENT_ID="${WALLET_CLIENT_ID:-zorgkantoor-wallet}"
REDIRECT_URI="${REDIRECT_URI:-https://zorgkantoor-wallet.vuggie.net/callback}"
WEB_ORIGIN="${WEB_ORIGIN:-https://zorgkantoor-wallet.vuggie.net}"

echo "Creating wallet client: $WALLET_CLIENT_ID"
curl -sS -X POST "$KC_BASE/admin/realms/$REALM/clients"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H "Content-Type: application/json"   -d "{
    \"clientId\":\"$WALLET_CLIENT_ID\",
    \"enabled\":true,
    \"publicClient\":true,
    \"standardFlowEnabled\":true,
    \"directAccessGrantsEnabled\":false,
    \"redirectUris\":[\"$REDIRECT_URI\"],
    \"webOrigins\":[\"$WEB_ORIGIN\"]
  }"   -w "\nHTTP=%{http_code}\n"

echo
echo "MANUAL (one-time): enable OID4VCI for $WALLET_CLIENT_ID:"
echo "Clients -> $WALLET_CLIENT_ID -> Advanced -> OpenID for Verifiable Credentials -> Enable OID4VCI"
