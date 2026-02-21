import express from "express";
import crypto from "crypto";
import { decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from "jose";

const app = express();
// If you're behind a reverse proxy (Cloudflare/Nginx), this helps req.protocol/req.get('host') behave.
app.set("trust proxy", true);
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 8081;

// Keycloak config (verifier)
const KC_ISSUER = process.env.KC_ISSUER; // e.g. https://vecozo-keycloak.vuggie.net/realms/vc-demo-clean
if (!KC_ISSUER) throw new Error("KC_ISSUER env var is required");

// Credential config (your demo id)
const CRED_CONFIG_ID = process.env.CRED_CONFIG_ID || "zorgkantoor-jwtvc";

// Issuer signing key (ES256)
const ISSUER_KID = process.env.ISSUER_KID || "issuer-es256-1";
const ISSUER_JWK = JSON.parse(process.env.ISSUER_JWK || "null");
if (!ISSUER_JWK) throw new Error("ISSUER_JWK env var is required (a JWK for ES256)");

function issuerPublicJwk() {
  // Publish only public parameters (never leak private "d")
  const pub = { ...ISSUER_JWK };
  delete pub.d; delete pub.p; delete pub.q; delete pub.dp; delete pub.dq; delete pub.qi; delete pub.oth;
  pub.kid = pub.kid || ISSUER_KID;
  pub.use = pub.use || "sig";
  pub.alg = pub.alg || "ES256";
  return pub;
}

// Public JWKS endpoint for verifiers (CIZ) to verify VC signatures.
// This is intentionally separate from Keycloak's JWKS (which is for access tokens).
app.get("/.well-known/jwks.json", (req, res) => {
  try {
    res.json({ keys: [issuerPublicJwk()] });
  } catch (e) {
    res.status(500).json({ error: "server_error", error_description: e.message });
  }
});

// very small in-memory nonce store
const nonces = new Map(); // access_token_hash -> { nonce, expMs }

function b64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function sha256(s) {
  return crypto.createHash("sha256").update(s).digest();
}


// did:web resolver (enterprise pragmatic)
// kid format expected: did:web:host[#fragment] e.g. did:web:zorgkantoor-wallet.vuggie.net#key-1
function didWebToDidJsonUrl(did) {
  const id = (did || "").trim();
  if (!id.startsWith("did:web:")) throw new Error(`Unsupported DID method in kid: ${id}`);
  // did:web:host(:path:segments) -> https://host/path/segments/did.json
  // spec: colon-separated path segments after host
  const rest = id.slice("did:web:".length);
  const parts = rest.split(":").filter(Boolean);
  const host = parts.shift();
  const path = parts.length ? "/" + parts.join("/") : "";
  // if no path segments => /.well-known/did.json
  return parts.length ? `https://${host}${path}/did.json` : `https://${host}/.well-known/did.json`;
}

// cache DID docs briefly to avoid hammering
const didCache = new Map(); // did -> { doc, fetchedAtMs }
async function fetchDidDoc(did) {
  const now = Date.now();
  const cached = didCache.get(did);
  if (cached && (now - cached.fetchedAtMs) < 60_000) return cached.doc;

  const url = didWebToDidJsonUrl(did);
  const res = await fetch(url, { headers: { "accept": "application/json", "user-agent": "issuer-service-demo" } });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`DID document fetch failed ${res.status} (${url}): ${body.slice(0, 200)}`);
  }
  const doc = await res.json();
  didCache.set(did, { doc, fetchedAtMs: now });
  return doc;
}

async function resolveDidPublicJwkByKid(kid) {
  // kid may be "did:web:...#key-1" or "did:web:...#<fragment>"
  const [did, fragment] = (kid || "").split("#");
  if (!did || !fragment) throw new Error("Invalid kid (expected did#fragment)");
  const doc = await fetchDidDoc(did);
  const vmId = `${did}#${fragment}`;
  const vm = (doc.verificationMethod || []).find(v => v.id === vmId);
  const pub = vm?.publicKeyJwk;
  if (!pub) throw new Error(`DID key not found in verificationMethod: ${vmId}`);
  return { did, vmId, publicKeyJwk: pub };
}

async function fetchJwks() {
  const base = (KC_ISSUER || "").replace(/\/+$/, ""); // trim trailing slashes
  const url = `${base}/protocol/openid-connect/certs`;

  console.log("Fetching JWKS:", url);

  const res = await fetch(url, {
    headers: {
      "accept": "application/json",
      "user-agent": "issuer-service-demo"
    }
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`JWKS fetch failed ${res.status}: ${body.slice(0, 200)}`);
  }
  return await res.json();
}


let jwksCache = { jwks: null, fetchedAt: 0 };
async function getJwksCached() {
  const now = Date.now();
  if (!jwksCache.jwks || (now - jwksCache.fetchedAt) > 60_000) {
    jwksCache.jwks = await fetchJwks();
    jwksCache.fetchedAt = now;
  }
  return jwksCache.jwks;
}

async function verifyKeycloakAccessToken(authzHeader) {
  if (!authzHeader?.startsWith("Bearer ")) throw new Error("Missing bearer token");
  const token = authzHeader.slice("Bearer ".length);

  const jwks = await getJwksCached();

  const { payload, protectedHeader } = await jwtVerify(token, async (header) => {
    const key = jwks.keys.find(k => k.kid === header.kid) || jwks.keys[0];
    if (!key) throw new Error("No JWKS key found");
    return await importJWK(key, header.alg);
  }, {
    issuer: KC_ISSUER,
  });

  return { token, payload, protectedHeader };
}

function getOrCreateNonce(accessToken) {
  const key = b64url(sha256(accessToken));
  const now = Date.now();
  const existing = nonces.get(key);
  if (existing && existing.expMs > now) return existing.nonce;

  const nonce = b64url(crypto.randomBytes(32));
  nonces.set(key, { nonce, expMs: now + 5 * 60_000 }); // 5 min
  return nonce;
}


async function verifyHolderProof(proofJwt, expectedAud, expectedNonce) {
  const parts = (proofJwt || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid proof jwt format");

  // Support both legacy (header.jwk) and DID-native (header.kid points to did:web)
  const header = decodeProtectedHeader(proofJwt);

  if (header.jwk) {
    // Legacy mode: proof contains embedded JWK
    const key = await importJWK(header.jwk, header.alg || "ES256");
    const { payload } = await jwtVerify(proofJwt, key, { audience: expectedAud });
    if (payload.nonce !== expectedNonce) throw new Error("Invalid nonce in proof");
    return { mode: "jwk", did: null, kid: null, jwk: header.jwk, payload };
  }

  if (!header.kid) throw new Error("Missing kid in proof header");
  // DID-native mode: kid is DID URL fragment
  const { did, vmId, publicKeyJwk } = await resolveDidPublicJwkByKid(header.kid);
  const key = await importJWK(publicKeyJwk, header.alg || "ES256");
  const { payload } = await jwtVerify(proofJwt, key, { audience: expectedAud });

  if (payload.nonce !== expectedNonce) throw new Error("Invalid nonce in proof");
  if (payload.iss && payload.iss !== did) throw new Error("Proof iss does not match DID");

  return { mode: "did", did, kid: vmId, jwk: publicKeyJwk, payload };
}

async function issueJwtVc({ holderKid, subjectDid, tokenPayload }) {

const issuerKey = await importJWK(ISSUER_JWK, "ES256");
const now = Math.floor(Date.now() / 1000);
const exp = now + 365 * 24 * 3600;

if (!subjectDid) throw new Error("subjectDid is required to issue DID-native VC");
if (!holderKid) throw new Error("holderKid is required to bind VC to holder DID key");

// Take everything the Authorization Server put under vc.credentialSubject in the access token
// and embed it into the issued VC's credentialSubject.
// - We always enforce the subject DID as credentialSubject.id.
// - We keep existing demo defaults for organization/role only if they are not provided by the token.
const tokenCs =
  tokenPayload?.vc?.credentialSubject && typeof tokenPayload.vc.credentialSubject === "object"
    ? tokenPayload.vc.credentialSubject
    : {};

const credentialSubject = {
  ...tokenCs,
  id: subjectDid
};

if (!credentialSubject.organization) credentialSubject.organization = "Zorgkantoor";
if (!credentialSubject.role) credentialSubject.role = "agent";

// Minimal JWT VC payload (DID-native holder binding via cnf.kid)
const vc = {
  iss: KC_ISSUER, // You can switch this to a DID for VECOZO later (e.g., did:web:vecozo...).
  sub: subjectDid,
  iat: now,
  nbf: now,
  exp,
  jti: crypto.randomUUID(),
  vc: {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "ZorgkantoorCredential"],
    credentialSubject
  },
  // DID-native holder binding
  cnf: { kid: holderKid }
};

const jwt = await new SignJWT(vc)
  .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: ISSUER_KID })
  .sign(issuerKey);

return jwt;
}

app.get("/health", (req, res) => res.json({ ok: true }));

// 1) Optional: explicit nonce endpoint (some wallets use it)
app.post("/nonce", async (req, res) => {
  try {
    const { token } = await verifyKeycloakAccessToken(req.headers.authorization);
    const nonce = getOrCreateNonce(token);
    res.json({ c_nonce: nonce, c_nonce_expires_in: 300 });
  } catch (e) {
    res.status(401).json({ error: "invalid_token", error_description: e.message });
  }
});

// 2) OID4VCI credential endpoint replacement
app.post("/credential", async (req, res) => {
  try {
    const { token, payload } = await verifyKeycloakAccessToken(req.headers.authorization);

    const requested = req.body?.credential_configuration_id;
    if (requested !== CRED_CONFIG_ID) {
      return res.status(400).json({ error: "invalid_request", error_description: `Unsupported credential_configuration_id: ${requested}` });
    }

    // Access token should contain authorization_details for openid_credential; accept if present.
    const authzDetails = payload.authorization_details || [];
    const ok = authzDetails.some(d => d.type === "openid_credential" && d.credential_configuration_id === CRED_CONFIG_ID);
    if (!ok) {
      return res.status(403).json({ error: "insufficient_scope", error_description: "Missing authorization_details for requested credential" });
    }

    const nonce = getOrCreateNonce(token);

    // Require proof
    const proofJwt = req.body?.proof?.jwt;
    if (!proofJwt) {
      return res.status(400).json({
        error: "invalid_proof",
        error_description: "Missing proof.jwt",
        c_nonce: nonce,
        c_nonce_expires_in: 300
      });
    }

    const expectedAud = process.env.ISSUER_AUD || `${req.protocol}://${req.get("host")}/credential`;
    let holder;
    try {
      holder = await verifyHolderProof(proofJwt, expectedAud, nonce);
    } catch (e) {
      return res.status(400).json({
        error: "invalid_proof",
        error_description: e.message,
        c_nonce: nonce,
        c_nonce_expires_in: 300
      });
    }

    const subjectDid = holder.mode === "did" ? holder.did : (payload.preferred_username || payload.sub);
    const holderKid = holder.mode === "did" ? holder.kid : null;
    const credential = await issueJwtVc({ holderKid, subjectDid, tokenPayload: payload });

    res.json({
      format: "jwt_vc",
      credential
    });
  } catch (e) {
    res.status(401).json({ error: "invalid_token", error_description: e.message });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Issuer service listening on :${PORT}`);
  console.log(`KC_ISSUER=${KC_ISSUER}`);
  console.log(`CRED_CONFIG_ID=${CRED_CONFIG_ID}`);
});