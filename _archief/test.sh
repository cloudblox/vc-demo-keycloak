KC_BASE="http://keycloak.zinl.nl:8090"
REALM="vc-demo"
ADMIN_TOKEN=$(./getAdminToken.sh)

# Get an admin token first (however you do it in your setup)
# Then:
curl -sS -X POST "$KC_BASE/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @client-scope-jwt-vc.json
