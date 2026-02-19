KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
CLIENT_ID="zorgkantoor-wallet"
REDIRECT_URI="http://localhost:8080/callback"
SCOPE="openid zorgkantoor-jwtvc"

AUTHZ_ENDPOINT=$(curl -sS \
  "$KC_BASE/realms/$REALM/.well-known/openid-configuration" \
  | jq -r .authorization_endpoint)

AUTH_URL="$AUTHZ_ENDPOINT\
?response_type=code\
&client_id=$CLIENT_ID\
&redirect_uri=$(python3 - <<EOF
import urllib.parse; print(urllib.parse.quote("$REDIRECT_URI"))
EOF
)\
&scope=$(python3 - <<EOF
import urllib.parse; print(urllib.parse.quote("$SCOPE"))
EOF
)\
&state=$STATE\
&code_challenge=$CHALLENGE\
&code_challenge_method=S256"

echo "$AUTH_URL"
