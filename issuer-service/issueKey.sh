node - <<'NODE'
import { generateKeyPair } from 'jose'
import { exportJWK } from 'jose'

const { privateKey } = await generateKeyPair('ES256', { extractable: true })
const jwk = await exportJWK(privateKey)

jwk.use = "sig"
jwk.alg = "ES256"
jwk.kid = "issuer-es256-1"

console.log(JSON.stringify(jwk))
NODE
