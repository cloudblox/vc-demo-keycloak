KC_BASE="https://vecozo-keycloak.vuggie.net"
REALM="vc-demo"
OFFER_CLIENT_ID="issuer-offer-service"
OFFER_CLIENT_SECRET="7ytAIfIbKhUoEja5dNdZGvdRNmhByYqg"
CRED_CONFIG_ID="zorgkantoor-jwtvc"
WALLET_CLIENT_ID="zorgkantoor-wallet"
TARGET_USERNAME="zorgkantoor-agent"
TOKEN_EP="$KC_BASE/realms/$REALM/protocol/openid-connect/token"



OFFER_TOKENS=$(curl -sS -X POST "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OFFER_CLIENT_ID" \
  -d "client_secret=$OFFER_CLIENT_SECRET")
OFFER_TOKEN=$(echo "$OFFER_TOKENS" | jq -r '.access_token')

echo "OFFER TOKEN $OFFER_TOKEN"

RESP=$(curl -sS -X GET \
  "$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer-uri?credential_configuration_id=$CRED_CONFIG_ID&pre_authorized=true&client_id=$WALLET_CLIENT_ID&username=$TARGET_USERNAME&type=uri" \
  -H "Authorization: Bearer $OFFER_TOKEN")

echo "RESP"
echo "$RESP" | jq

OFFER_NONCE=$(echo "$RESP" | jq -r '.nonce')
echo "OFFER_NONCE=$OFFER_NONCE"

# direct ophalen
OFFER_JSON=$(curl -sS -X GET \
  "$KC_BASE/realms/$REALM/protocol/oid4vc/credential-offer/$OFFER_NONCE" \
  -H "Authorization: Bearer $OFFER_TOKEN")

echo "$OFFER_JSON" | jq

PA_CODE=$(echo "$OFFER_JSON" | jq -r \
  '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]')








ACCESS_TOKEN=$(curl -sS -X POST "$TOKEN_EP" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  -d "pre-authorized_code=$PA_CODE" \
  -d "client_id=$WALLET_CLIENT_ID" | jq -r '.access_token')

echo "ACCESS_TOKEN_LEN=${#ACCESS_TOKEN}"
echo "ACCESS_TOKEN:"
echo "$ACCESS_TOKEN"



SCOPE_STR=$(
  echo "$ACCESS_TOKEN" | cut -d. -f2 \
  | tr '_-' '/+' \
  | awk '{print $0 "==="}' \
  | base64 -d 2>/dev/null \
  | jq -r '.scope'
)

echo "SCOPE=[$SCOPE_STR]"
echo -n "$SCOPE_STR" | od -An -tx1

