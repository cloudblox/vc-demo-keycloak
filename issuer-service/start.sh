npm i express jose

export PORT=8081
export KC_ISSUER="https://vecozo-keycloak.vuggie.net/realms/vc-demo"
export ISSUER_AUD="http://localhost:8081/credential"
export ISSUER_KID="issuer-es256-1"
export CRED_CONFIG_ID="membership-credential"
export ISSUER_JWK='{"kty":"EC","x":"wApJNG6bYLXD3ukdCSnkngsknz3zukuXeOIlHOBc6bA","y":"tSwmaAMUgsjbzEo8NAEow6Z0PLuKC0-HAuDZAEpdm6M","crv":"P-256","d":"1ZvHkKTDknReeStVf5tnlpzp58jxRr2EQtfm9Ou2Sf8","use":"sig","alg":"ES256","kid":"issuer-es256-1"}'
node server.mjs
