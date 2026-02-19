KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
CLIENT_ID="zorgkantoor-wallet"
REDIRECT_URI="https://zorgkantoor-wallet.vuggie.net/callback"
SCOPE="openid zorgkantoor-jwtvc"

OIDC_JSON="$(curl -sS "$KC_BASE/realms/$REALM/.well-known/openid-configuration")"
AUTHZ_ENDPOINT="$(echo "$OIDC_JSON" | jq -r .authorization_endpoint)"

VERIFIER="$(openssl rand -base64 48 | tr -d '=+/ ' | cut -c1-64)"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
STATE="$(openssl rand -hex 16)"

ENC_REDIRECT="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$REDIRECT_URI")"
ENC_SCOPE="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$SCOPE")"

echo "$AUTHZ_ENDPOINT?response_type=code&client_id=$CLIENT_ID&redirect_uri=$ENC_REDIRECT&scope=$ENC_SCOPE&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256"
