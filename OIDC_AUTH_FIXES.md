# OIDC Auth Fixes

A summary of fixes that came out of the `oidc-auth-test` exercise in
`openziti/ziti`. The scenarios that motivated each fix are noted.

## 1. Retry OIDC auth failures with exponential backoff

**Files:** `inc_internal/auth_method.h`, `includes/ziti/ziti.h`,
`library/oidc_auth.c`, `library/ziti.c`

Initial OIDC authentication used to fail hard if the controller could not be
reached or if the token request returned an error. In an HA fleet that means
a single controller hiccup at SDK startup wedges the client until it is
restarted.

This fix:

- Adds exponential backoff with jitter (5s-60s) for OIDC auth and config
  failures instead of failing immediately.
- Adds a new `auth_timeout` option on `ziti_options` that caps how long the
  retry loop runs (`0` = retry forever, the default).
- Resets the OIDC URL iterator on config failure so all known endpoints are
  retried on subsequent attempts.
- Reports `OIDC_TOKEN_FAILED` (not `ZITI_AUTHENTICATION_FAILED`) for transient
  token errors so the retry layer can distinguish retryable from fatal.
- Cleans up the retry timer on `auth_stop` and `auth_free`.

## 2. Add NULL identity guards and retry failed identity loads

**Files:** `library/connect.c`, `library/ziti.c`

When `update_identity_data` failed before the identity had ever been loaded,
later code could dereference the still-NULL identity and crash. We also gave
up after the first failure, so a transient controller error during startup
left the SDK with no identity.

This fix:

- Adds NULL checks for `ziti_get_identity()` in `connect_get_service_cb` and
  `ziti_channel_start_connection`.
- Guards `zid->name` access in `ziti_dial_opts_for_addr` with a NULL check.
- Retries the identity fetch after 5s when `update_identity_data` fails and
  no identity has been loaded yet.

## 3. Retry connect on `ZITI_AUTHENTICATION_FAILED`

**File:** `library/connect.c`

When an OIDC token refresh completed mid-flight, an outstanding edge-session
POST could come back with `ZITI_AUTHENTICATION_FAILED` (the SDK's mapping of
the controller's `UNAUTHORIZED` code) rather than `ZITI_NOT_AUTHORIZED`. Only
`ZITI_NOT_AUTHORIZED` triggered the force-refresh + restart path, so the
connection failed even though a fresh token was now in hand.

This fix treats both `ZITI_NOT_AUTHORIZED` and `ZITI_AUTHENTICATION_FAILED` as
retryable in `connect_get_net_session_cb`. `restart_connect` is bounded by
`MAX_CONNECT_RETRY` so a genuinely dead token cannot loop forever.

## 4. Per-request controller timeout and 5xx endpoint rotation

**File:** `library/ziti_ctrl.c`

Two related controller-resilience problems:

1. A controller request could hang for many minutes if the underlying TCP
   connection was silently dropped (a network partition or middlebox NAT
   timeout) — the SDK relied on kernel TCP keepalive (~2 hours by default)
   to give up.
2. A controller returning `5xx` was treated as a normal response: the body
   was delivered to the caller but the SDK kept hitting that same controller
   for subsequent requests instead of trying another.

This fix:

- Adds a per-request 30s watchdog (`ZITI_CTRL_REQ_TIMEOUT`) that calls
  `tlsuv_http_req_cancel` if a response has not arrived. The cancel surfaces
  as `UV_ECANCELED` to the existing error path, which now distinguishes a
  timer-induced cancel (treat as controller failure, rotate) from a
  shutdown-induced cancel (silent, no rotation) using a new `timed_out`
  flag.
- On a `5xx` response, marks the current controller offline and rotates to
  the next endpoint (only when `active_reqs == 0` to avoid racing rotations
  when many requests fail simultaneously).
- Tracks the in-flight request handle and timer on the `ctrl_resp` so the
  watchdog can be stopped cleanly from `ctrl_default_cb` and
  `ctrl_body_cb`.

## 5. Rotate OIDC token refresh across HA controllers

**Files:** `inc_internal/auth_method.h`, `inc_internal/oidc.h`,
`library/oidc.c`, `library/oidc_auth.c`, `library/ziti.c`

In an HA controller setup, every refresh request previously went to whichever
single controller the SDK had originally negotiated OIDC against (the one
whose `/version` it called at startup). When that controller went away, the
refresh would fail, the OIDC client would retry the same dead URL on a
backoff, and the SDK never learned to ask one of the other controllers.

Two related sub-problems were also addressed:

- A stuck in-flight refresh (TCP dropped silently) blocked new refreshes
  because `oidc_client_refresh` returned `UV_EALREADY`.
- The OIDC URL pool was seeded only from the `/version` reply, which only
  reports the local controller's OIDC URL. The persisted identity already
  knows the full HA controller list.

This fix:

- Adds a new `OIDC_REFRESH_TRANSIENT_FAIL` status so the OIDC client can hand
  transient refresh failures up to the auth method instead of scheduling its
  own internal retry against the same URL.
- Cancels a stuck in-flight refresh in `oidc_client_refresh` rather than
  returning `UV_EALREADY`, so a force-refresh actually starts a new request.
- Adds `oidc_auth_merge_ctrl_urls` which extends the auth method's URL
  rotation pool with normalized `scheme://host[:port]` entries from a list
  of controller URLs (deduplicating by normalized form).
- Seeds the rotation pool from `ztx->config.controllers` in
  `version_pre_auth_cb` so initial auth can spread across all known
  controllers, and from `apis.oidc` in `ctrl_list_cb` after the controller
  list returns so subsequent refreshes know the authoritative OIDC URLs.
- Adds a `rotate_and_refresh` path in `oidc_auth.c` that advances `cur_url`
  on transient refresh failure, reconfigures the OIDC client at the next
  controller, and applies an exponential backoff once an entire rotation
  has been exhausted.

