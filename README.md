# VC Demo, pre authorized code flow

This repo contains a demo that uses Keycloak as Identity provider according to the [Pre-Authorized Code Flow](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) OID4VC specification.
This is the technical material that will be used in the February hackathon with Zorginstituut Nederland and Vecozo.

In this demo we emulate a simple flow:

- Zorgkantoor (Wallet) calls CIZ (Verifier) with a VC that has been Issued by Vecozo (Issuer)

This Verifiable Credential demo aligns with European and Dutch healthcare regulatory ambitions by implementing decentralized, cryptographically verifiable identity and authorization mechanisms consistent with the eIDAS 2.0 framework, the European Digital Identity Wallet, and Dutch national initiatives such as the Landelijk Vertrouwenstelsel, NEN 7510, and the MedMij and Nuts trust frameworks, enabling secure, privacy-preserving, and interoperable exchange of healthcare identity and authorization attributes under the principles of data minimization, strong authentication, and verifiable trust.


```mermaid
sequenceDiagram
  autonumber
  participant W as Zorgkantoor Wallet<br/>(localhost:3000)
  participant AS as Keycloak Authorization Server<br/>(token endpoint)
  participant IS as Keycloak OID4VC Issuer<br/>(credential endpoint)
  participant VCStore as Wallet VC Store<br/>(/credentials/latest)
  participant V as CIZ Verifier / Resource API<br/>(localhost:8002)

  Note over W,AS: 1) Autorisatie om issuance te mogen doen (OAuth/OIDC)
  W->>AS: Run getToken.sh → token request<br/>client auth + scope for credential
  AS-->>W: access_token (Bearer)

  Note over W,IS: 2) Issuance start: wallet vraagt credential aan
  W->>IS: POST /credential (1e poging)<br/>Authorization: Bearer access_token<br/>body: {credential_configuration_id, ...}<br/>(proof ontbreekt of ongeldig)
  IS-->>W: error=invalid_proof + c_nonce + c_nonce_expires_in

  Note over W,IS: 3) Wallet bewijst sleutelbezit (Proof-of-Possession)
  W->>W: Maak proof_jwt<br/>claims: aud=credential_endpoint<br/>nonce=c_nonce<br/>sign met holder private key
  W->>IS: POST /credential (2e poging)<br/>Authorization: Bearer access_token<br/>body: {..., proof:{proof_type:"jwt", jwt:proof_jwt}}
  IS-->>W: VC_JWT (ondertekend door issuer)

  Note over W,VCStore: 4) Wallet slaat credential op (zodat GETVC werkt)
  W->>VCStore: Store VC_JWT as latest credential
  VCStore-->>W: OK

  Note over W,V: 5) Presentatie + toegang (jullie werkende demo-flow)
  W->>VCStore: GET /credentials/latest
  VCStore-->>W: { credential: VC_JWT }

  W->>W: Maak VP_JWT (Verifiable Presentation)<br/>aud="ciz-verifier"<br/>embed VC_JWT<br/>sign met holder key
  W->>V: POST /hello<br/>{ vp_jwt: VP_JWT }
  V->>V: Verify VP signature + aud<br/>Verify embedded VC (issuer signature, exp)
  V->>V: Authorize op basis van VC claims (role/sector/etc.)
  V-->>W: 200 OK (ALLOW) of 403 (DENY)
  ```


# Pre Requisites

- This Demo is based on Keycloak version `26.5.3`

## Configure Realm

- Create a new REALM in keycloak (for e.g. vc-demo)
- This realm will act as:
  1. Authorization Server (OFFER_TOKEN via client_credentials)
  1. Credential Offer Service (OFFER_HANDLE / offer URI)
  1. Authorization Server (wallet: pre-authorized_code → ACCESS_TOKEN)
  1. Credential Issuer (credential endpoint produces VC payload)
  1. Credential Signing Authority (signs VC)
- In Realm settings enable `Verifiable Credentials`
- Configure a OID4VC scope; this is not supported by the UI yet; just execute the `./createScope.sh` script; this will create a client scope named: `membership-credential`
- Configure Identity Attribute, Adde `uzovi`; in Realm settings, User Profile , add Attribute `uzovi`
- In the UI, after creating the `membership-credential` go to client scopes, select `membership-credential` and add a mapper. Configure new mapper (User Attribute mapper), name it `uzovi` *Note: this is still very buggy in Keycloak, so we need to create a OIDC scope as well in stead of a OID4VC scope only*
- Client scopes → Create client scope `wallet-token-claims` Protocol: openid-connect
	- Client scopes → wallet-token-claims → Mappers → Create
	- Mapper type: User Attribute, Name: uzovi
  - Maker sure you map the uzovi user attribute to token claim name `vc.credentialSubject.uzovi`
- Assign to wallet client:
	- Clients → zorgkantoor-wallet → Client scopes → Add client scope
	- Select wallet-token-claims, Add as Default

The following identities are initially needed for this demo to work;
- Credential Subject; user `zorgkantoor-agent`
- Wallet; public client `zorgkantoor-wallet`
- Issuer Backend; confidential client `issuer-offer-service`


## Configure Issuer Backend client

- Within your new REALM create a confidential client named `issuer-offer-service`, type OpenID Connect; this is needed to create an initial offer token, it needs the following:
  - Client Authentication On
  - Service Accounts Roles checked (this will create an internal keycloak user service-account-[YOUR CLIENT NAME])
  - Authorize to create offers:
    - In Service Account Role assign a REALM role with the name `credential-offer-create`
    - OIDC4VC enabled, you can find this under "Advanced"
- for this client: No Redirect URLs/ No OIDC standard flow/ No profile mappers/ nothing to do with VC

## Configure User (Identity)

In your realm go to User and create `zorgkantoor-agent`
Keep everything default, and fill in a `uzovi` identifier for eg 9999

## Configure Wallet client (Credential holder)

- Create client `zorgkantoor-wallet`, type OpenID Connect; This client will receive the credential offer form the `issuer-offer-service` and will exchange the `pre-authorized-code` for an actual `access token`. This access token will be used later by the Issuer service (the service that actually creates the VC). Please note that client works with the `pre-authorized-code` which is an internal Keycloak authorization credential
- Set client as a public client
  - Client authentication: OFF (public client)
  -	Standard flow: OFF
  -	Direct access grants: OFF
  -	Implicit flow: OFF
  -	Service accounts: OFF
- OIDC4VC enabled, you can find this under "Advanced"
- Client scope; assign `membership-credential`credential default (this is the one you created a realm setup phase)

## Create config file

In your folder create a .env file with the following content
```
KC_CONTAINER='keycloak'
KC_URL='http://localhost:8443'
KC_DB_USERNAME='keycloak'
KC_DB_PASSWORD='[ YOUR KC DB PASSWD ]'
KEYCLOAK_ADMIN='admin'
KEYCLOAK_ADMIN_PASSWORD='YOUR KC ADMIN PASSWD'
OFFER_SERVICE_CLIENT_SECRET='YOUR KC OFFER SERVICE CLIENT PASSWD'
REALM='vc-demo'
WALLET_PROOF_EP="https://zorgkantoor-wallet.vuggie.net/make-proof"
```

# Run demo

- Bring up Infrastructure; 
  - `docker compose up -d`
  - Start issuer service (creates VC); cd issuer-service; ./start.sh 

- create VC
  - `./createVC.sh`

- get latest VC from Issuer

```
VC_JWT=$(curl -sS http://localhost:3000/credentials/latest | jq -r .credential)
echo "VC_JWT_LEN=${#VC_JWT}"
```

- Make VP (needed when calling the Verifier)

```
VP_JWT=$(curl -sS -X POST http://localhost:3000/make-vp \
  -H "Content-Type: application/json" \
  -d '{"verifier_aud":"ciz-verifier"}' | jq -r .vp_jwt)
```

- Call the Verifier (CIZ)

```
curl -sS -X POST "http://localhost:8002/hello" \
  -H "Content-Type: application/json" \
  -d "{\"vp_jwt\":\"$VP_JWT\"}" | jq .
```

This should return something like this:
![alt text](image.png)