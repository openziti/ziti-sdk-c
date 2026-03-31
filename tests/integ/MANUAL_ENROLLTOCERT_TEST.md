# Manual enrollToCert Testing Notes

Tested 2026-03-31.

## Environment

- **Ziti controller + CLI**: dev build from openziti/ziti main branch (v2.0 pre-release)
- **Ziti C SDK**: enroll-to-cert branch of ziti-sdk-c
- **OIDC provider**: Keycloak 26.x via Docker

## Keycloak Setup

```bash
docker run -d -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak start-dev
```

1. Create realm `ziti-test` at http://localhost:8080/admin
2. Create client `ziti-enrolltocert`:
   - Client authentication: Off (public client for PKCE)
   - Standard flow: enabled
   - Valid redirect URIs: `http://localhost:20314/*`
   - Web origins: `+`
3. Create user `testuser` with password `testpass` (non-temporary)

## Ziti Controller Setup

```bash
# Create ext-jwt-signer (no --enroll-auth-policy)
ziti edge create ext-jwt-signer test-enroll-signer \
  "http://localhost:8080/realms/ziti-test" \
  --jwks-endpoint "http://localhost:8080/realms/ziti-test/protocol/openid-connect/certs" \
  --external-auth-url "http://localhost:8080/realms/ziti-test" \
  --client-id "ziti-enrolltocert" \
  --audience "account" \
  --enroll-to-cert
```

Notes:
- `--audience "account"` must match Keycloak's `aud` claim (Keycloak sets
  `aud` to `account` by default for access tokens, not the client ID)
- Do NOT specify `--enroll-auth-policy` - the default policy works; a custom
  policy with `--primary-cert-allowed` caused the controller to skip cert
  issuance
- Requires controller v2.0+ (v1.6.12 silently ignores `--enroll-to-cert`)

## Running sample_enroll

**Public CA controller** (network JWT fetched automatically):

```bash
ZITI_LOG=4 ./build/programs/sample_enroll/RelWithDebInfo/sample_enroll \
  https://ctrl.example.com:443 /tmp/test-enrolled.json
```

**Private CA controller** (network JWT provided out of band):

```bash
# Fetch network JWT manually (conscious trust decision with -k)
curl -sk https://localhost:1280/network-jwts | jq -r '.data[0].token' > /tmp/network.jwt

ZITI_LOG=4 ./build/programs/sample_enroll/RelWithDebInfo/sample_enroll \
  https://localhost:1280 /tmp/test-enrolled.json --jwt /tmp/network.jwt
```

### Trust bootstrapping

The SDK uses the network JWT to verify the controller's identity before
fetching the CA bundle. This prevents MITM attacks during bootstrap.

- If no `--jwt` is given, the SDK fetches the network JWT from the
  controller's `/network-jwts` endpoint. This requires the controller's
  TLS certificate to be verifiable by the OS trust store (publicly-trusted CA).
- If `--jwt` is given, it is used directly to verify the controller,
  allowing privately-signed controllers.

### What the program does

1. Fetches network JWT (or uses provided one) and verifies controller identity
2. Fetches CA bundle from `/.well-known/est/cacerts` over the verified connection
3. Connects to controller, discovers ext-jwt-signers
4. Selects the signer with `enrollToCertEnabled`
5. Prints an OIDC auth URL (also logged at INFO level with full query params)
6. User opens URL in browser, authenticates as `testuser`/`testpass`
7. SDK receives JWT, generates keypair + CSR, calls `POST /enroll/token`
8. Controller creates identity and returns response
9. Identity config saved to output file

## Results

**What worked:**
- Full OIDC flow: discovery, browser auth, token exchange
- CSR generation and submission to controller
- Identity auto-creation on the controller
- Controller signed the CSR and returned a client certificate
- SDK stored cert + key in config and fired ZitiConfigEvent
- Identity config saved with cert, key, and CA bundle

**Issues found and fixed during testing:**

1. **JWT `kid` header required** - the v2.0 controller requires a `kid`
   (Key ID) in the JWT header matching the signer's configured kid. For
   `--cert-file` signers, the kid must be explicitly set via `--kid`
   when creating the signer. The integration tests now compute the cert
   fingerprint (SHA-1 of DER) and set it as the kid.

2. **Response model field name mismatch** - the `/enroll/token` endpoint
   returns `cert` and `ca` fields, but the C SDK's response model
   expected `certificate` and `cas`. Created a separate
   `ziti_enrollment_cert_resp` model with the correct field names.

3. **Duplicate identity** - re-enrolling with the same `sub` claim
   fails with `ENROLLMENT_IDENTITY_ALREADY_ENROLLED`. Must delete the
   existing identity before re-testing.

4. **Premature config event** - the SDK fires `ZitiConfigEvent` during
   context initialization (before enrollToCert). The zitilib handler must
   ignore config events until the cert is present.

## Cleanup

```bash
# Delete test identity
ziti edge list identities   # find the auto-created identity
ziti edge delete identity <id>

# Delete signer
ziti edge delete ext-jwt-signer test-enroll-signer

# Stop Keycloak
docker stop <container-id>
```
