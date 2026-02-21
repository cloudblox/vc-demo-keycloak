#!/usr/bin/env bash
set -euo pipefail

# Ensure local jose
if [ ! -d node_modules/jose ]; then
  npm init -y >/dev/null 2>&1 || true
  npm i jose >/dev/null 2>&1
fi

node - <<'NODE'
import { generateKeyPair, exportJWK } from "jose";

const { privateKey } = await generateKeyPair("ES256", { extractable: true });

const jwk = await exportJWK(privateKey);
jwk.kid = "issuer-es256-1";
jwk.use = "sig";
jwk.alg = "ES256";

console.log(JSON.stringify(jwk));
NODE
