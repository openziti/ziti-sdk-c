# Manual Enrollment Testing Notes

Tested 2026-04-01.

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

Note: `start-dev` uses in-memory storage. Users are lost if the container
is recreated, though the realm/client may survive if imported.

## Ziti Controller Setup

```bash
# Create ext-jwt-signer
ziti edge create ext-jwt-signer test-enroll-signer \
  "http://localhost:8080/realms/ziti-test" \
  --jwks-endpoint "http://localhost:8080/realms/ziti-test/protocol/openid-connect/certs" \
  --external-auth-url "http://localhost:8080/realms/ziti-test" \
  --client-id "ziti-enrolltocert" \
  --audience "account" \
  --enroll-to-cert

# To also test enrollToToken:
ziti edge update ext-jwt-signer test-enroll-signer --enroll-to-token
```

Notes:
- `--audience "account"` must match Keycloak's `aud` claim (Keycloak sets
  `aud` to `account` by default for access tokens, not the client ID)
- Do NOT specify `--enroll-auth-policy` - the default policy works; a custom
  policy with `--primary-cert-allowed` caused the controller to skip cert
  issuance
- Requires controller v2.0+ (v1.6.12 silently ignores `--enroll-to-cert`)

## Three Enrollment Modes

### Trust bootstrapping

The SDK uses the network JWT to verify the controller's identity before
fetching the CA bundle.

- **URL path** (public CA): fetches the network JWT from `/network-jwts`,
  requires the controller's TLS cert to be verifiable by the OS trust store.
- **JWT path** (private CA): fetch network JWT out of band and pass via
  `--jwt`. Use `curl -sk` as a conscious trust decision.

```bash
# For private CA controllers:
curl -sk https://localhost:1280/network-jwts | jq -r '.data[0].token' > /tmp/network.jwt
```

### Mode 1: `--enrollTo none` (or no flag) - Pre-created identity

Identity is pre-created by an admin. Enrollment just bootstraps the config
(CA + controller URL). No OIDC, no browser prompt. Authentication happens
later when the application runs with the identity.

```bash
# Create identity on the controller first
ziti edge create identity testuser-precreated --auth-policy default

# Bootstrap config - returns immediately, no OIDC
ZITI_LOG=4 ./build/programs/sample_enroll/RelWithDebInfo/sample_enroll \
  https://localhost:1280 /tmp/test-none.json --jwt /tmp/network.jwt
```

Expected: identity JSON with CA + controller URL, no cert/key. No browser
prompt.

### Mode 2: `--enrollTo cert` - enrollToCert

Auto-creates identity on the controller. OIDC auth + CSR exchange for a
client certificate.

```bash
# Clean up any existing identity first
ziti edge list identities 'name contains "testuser"'
ziti edge delete identity <id>

ZITI_LOG=4 ./build/programs/sample_enroll/RelWithDebInfo/sample_enroll \
  https://localhost:1280 /tmp/test-cert.json --jwt /tmp/network.jwt --enrollTo cert
```

Expected: browser opens for OIDC auth, identity JSON with CA + controller
URL + cert + key.

### Mode 3: `--enrollTo token` - enrollToToken

Returns bootstrap config immediately (same as none mode). The actual
identity auto-creation happens on first auth when the SDK runs with
`enroll_mode = ziti_enroll_token`.

```bash
ZITI_LOG=4 ./build/programs/sample_enroll/RelWithDebInfo/sample_enroll \
  https://localhost:1280 /tmp/test-token.json --jwt /tmp/network.jwt --enrollTo token
```

Expected: identity JSON with CA + controller URL, no cert/key. No browser
prompt. Requires signer with `enrollToTokenEnabled`.

## Results

**What worked:**
- All three enrollment modes tested successfully
- enrollToCert: full OIDC flow, CSR generation, cert exchange, identity saved
- enrollToToken: bootstrap config returned immediately, no OIDC
- none: bootstrap config returned immediately, no OIDC
- Network JWT verification prevents MITM during bootstrap

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

5. **Pre-created identity regression** - enrollToCert changes caused the
   SDK to unconditionally try enrollment when no cert was present. Fixed
   by adding `ziti_enroll_mode` enum to make enrollment intent explicit.

6. **enroll_mode not propagated** - `copy_opt` stored the mode in
   `ztx->opts.enroll_mode` but `external_auth.c` read `ztx->enroll_mode`.
   Fixed by reading from `ztx->opts.enroll_mode`.

## Cleanup

```bash
# Delete test identities
ziti edge list identities
ziti edge delete identity <id>

# Delete signer
ziti edge delete ext-jwt-signer test-enroll-signer

# Stop Keycloak
docker stop <container-id>
```
