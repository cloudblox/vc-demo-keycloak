#!/usr/bin/env bash
set -euo pipefail

KC_BASE="${KC_BASE:-https://vecozo-keycloak.vuggie.net}"
REALM="${REALM:-vc-demo-clean}"
KC_BASE="${KC_BASE%/}"

ADMIN_TOKEN="${ADMIN_TOKEN:-$(./getAdminToken.sh)}"

USERNAME="${TARGET_USERNAME:-zorgkantoor-agent}"

echo "Creating user: $USERNAME"
curl -sS -X POST "$KC_BASE/admin/realms/$REALM/users"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H "Content-Type: application/json"   -d "{
    \"username\":\"$USERNAME\",
    \"enabled\":true,
    \"firstName\":\"Zorgkantoor\",
    \"lastName\":\"Agent\",
    \"email\":\"$USERNAME@example.org\",
    \"emailVerified\":true
  }"   -w "\nHTTP=%{http_code}\n"
