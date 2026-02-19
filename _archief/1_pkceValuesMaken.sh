VERIFIER=$(openssl rand -base64 48 | tr -d '=+/ ' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" \
  | openssl dgst -binary -sha256 \
  | openssl base64 -A \
  | tr '+/' '-_' | tr -d '=')

STATE=$(openssl rand -hex 16)
echo "verifier:"
echo $VERIFIER
echo "state:"
echo $STATE
