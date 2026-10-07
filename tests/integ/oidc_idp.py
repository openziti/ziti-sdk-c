#  Copyright (c) 2026.  NetFoundry Inc
#
#  SPDX-License-Identifier: Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""A minimal OpenID Connect provider for the external JWT integration tests, built on Authlib.

It runs in-process on a thread and plays the external IdP of an ``ext-jwt-signer``:

* discovery and JWKS, with a fixed issuer ``http://127.0.0.1:<port>``
* one public client (no secret) whose redirect URIs are given by the caller
* ``authorization_code`` with PKCE (S256), ``password`` and ``refresh_token`` grants
* RS256 ``id_token`` *and* ``access_token``, both JWTs with ``aud`` = client id and ``sub`` = ``email`` = user

Users are an email -> password dict; ``/authorize`` shows a bare login form, so a test can drive
the browser step with plain HTTP: see ``OidcIdp.login`` and ``OidcIdp.password_grant``.
"""

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import Flask, jsonify, request
from joserfc import jwt
from joserfc.jwk import RSAKey
from werkzeug.serving import make_server

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import ClientMixin, TokenMixin, grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import AuthorizationCodeMixin
from authlib.oidc.core.grants import OpenIDCode, OpenIDToken

SCOPES = ["openid", "email", "profile", "offline_access"]
GRANT_TYPES = ["authorization_code", "password", "refresh_token"]
TOKEN_TTL = 3600

LOGIN_FORM = ('<form method="post">'
              '<input name="login"><input name="password" type="password"><button>login</button>'
              '</form>')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# no proxies (this is all loopback) and no redirects (the interesting part of a login is the redirect itself)
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _request(url, form=None):
    """GET, or POST of ``form``: returns ``(status, headers, body)`` and never raises on an http error status."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    try:
        with _opener.open(urllib.request.Request(url, data=data), timeout=10) as resp:
            return resp.status, resp.headers, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


class _Client(ClientMixin):
    """A public client: no secret, so PKCE is what protects the authorization code."""

    def __init__(self, client_id, redirect_uris):
        self.client_id = client_id
        self.redirect_uris = list(redirect_uris)

    def get_client_id(self): return self.client_id
    def get_default_redirect_uri(self): return self.redirect_uris[0]
    def check_redirect_uri(self, redirect_uri): return redirect_uri in self.redirect_uris
    def check_client_secret(self, client_secret): return False
    def check_endpoint_auth_method(self, method, endpoint): return method == "none"
    def check_response_type(self, response_type): return response_type == "code"
    def check_grant_type(self, grant_type): return grant_type in GRANT_TYPES

    def get_allowed_scope(self, scope):
        return " ".join(s for s in (scope or "").split() if s in SCOPES)


class _AuthCode(AuthorizationCodeMixin):
    def __init__(self, code, client_id, redirect_uri, scope, user, data):
        self.code, self.client_id, self.redirect_uri, self.scope, self.user = code, client_id, redirect_uri, scope, user
        self.code_challenge = data.get("code_challenge")
        self.code_challenge_method = data.get("code_challenge_method")
        self.nonce = data.get("nonce")
        self.auth_time = int(time.time())

    def get_redirect_uri(self): return self.redirect_uri
    def get_scope(self): return self.scope
    def get_nonce(self): return self.nonce
    def get_auth_time(self): return self.auth_time
    def get_acr(self): return None
    def get_amr(self): return None


class _CodeChallenge(CodeChallenge):
    """PKCE with S256 only, as advertised in the discovery document (Authlib also accepts ``plain``)."""
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]


class _RefreshToken(TokenMixin):
    def __init__(self, token, client_id, user, scope):
        self.token, self.client_id, self.user, self.scope = token, client_id, user, scope
        self.revoked = False
        self.expires_at = time.time() + 24 * TOKEN_TTL

    def check_client(self, client): return client.get_client_id() == self.client_id
    def get_scope(self): return self.scope
    def get_expires_in(self): return int(self.expires_at - time.time())
    def is_expired(self): return time.time() > self.expires_at
    def is_revoked(self): return self.revoked
    def get_user(self): return self.user


class OidcIdp:
    """``with OidcIdp(client_id, redirect_uris) as idp:`` -- ``idp.issuer`` is valid inside the block."""

    def __init__(self, client_id, redirect_uris, users=None, port=0, host="127.0.0.1"):
        self.client = _Client(client_id, redirect_uris)
        self.users = dict(users or {})                      # email -> password
        self.key = RSAKey.generate_key(2048, parameters={"use": "sig", "alg": "RS256"}, auto_kid=True)
        self._codes = {}
        self._refresh_tokens = {}
        self.app = Flask(__name__)
        self._configure_authlib()
        self._add_routes()
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        self._server = make_server(host, port, self.app, threaded=True)
        self.issuer = f"http://{host}:{self._server.server_port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def add_user(self, email, password):
        self.users[email] = password

    # ---- for tests: what a user and their browser would do ---------------------------------
    def password_grant(self, email, scope="openid email offline_access"):
        """Tokens for a user without a browser: ``{"access_token", "id_token", "refresh_token", ...}``."""
        status, _, body = _request(f"{self.issuer}/token", {
            "grant_type": "password", "client_id": self.client.client_id,
            "username": email, "password": self.users[email], "scope": scope})
        if status != 200:
            raise RuntimeError(f"password grant for {email} failed: {status} {body}")
        return json.loads(body)

    def login(self, authorize_url, email):
        """Play the browser at ``authorize_url`` (as handed out by the sdk): show the login page, submit the
        credentials of ``email`` and return where the idp redirects to, ``<redirect_uri>?code=...&state=...``.
        The caller delivers that to the redirect uri, i.e. the sdk's loopback listener."""
        status, _, body = _request(authorize_url)
        if status != 200:
            raise RuntimeError(f"login page at {authorize_url} failed: {status} {body}")
        status, headers, body = _request(authorize_url, {"login": email, "password": self.users[email]})
        if status not in (302, 303):
            raise RuntimeError(f"login of {email} failed: {status} {body}")
        return headers["Location"]

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._server.shutdown()
        self._thread.join(timeout=5)

    def __enter__(self): return self.start()
    def __exit__(self, *exc): self.stop()

    # ---- tokens -----------------------------------------------------------------------------
    def _sign(self, claims):
        now = int(time.time())
        claims = {"iss": self.issuer, "iat": now, "exp": now + TOKEN_TTL, **claims}
        return jwt.encode({"alg": "RS256", "kid": self.key.kid}, claims, self.key)

    def _access_token(self, client, grant_type, user=None, scope=None):
        # a JWT, not an opaque string: an ext-jwt-signer validates whichever token the SDK sends
        return self._sign({"sub": user, "email": user, "aud": client.get_client_id(), "scope": scope})

    # ---- authlib wiring ---------------------------------------------------------------------
    def _configure_authlib(self):
        idp = self
        self.app.config.update(
            OAUTH2_ACCESS_TOKEN_GENERATOR=self._access_token,
            OAUTH2_REFRESH_TOKEN_GENERATOR=True,
            OAUTH2_TOKEN_EXPIRES_IN={g: TOKEN_TTL for g in GRANT_TYPES},
        )

        def save_token(token, request):
            if "refresh_token" in token:
                idp._refresh_tokens[token["refresh_token"]] = _RefreshToken(
                    token["refresh_token"], request.client.get_client_id(), request.user, token.get("scope", ""))

        self.server = AuthorizationServer(
            self.app,
            query_client=lambda cid: idp.client if cid == idp.client.client_id else None,
            save_token=save_token)

        class IdTokenMixin:                 # the id_token, shared by every grant that issues one
            def resolve_client_private_key(self, client): return idp.key
            def get_encode_header(self, client): return {"alg": "RS256", "kid": idp.key.kid}
            def get_client_claims(self, client): return {"iss": idp.issuer, "aud": client.get_client_id()}

            def generate_user_info(self, user, scope):
                return {"sub": user, **({"email": user} if "email" in scope else {})}

        class CodeIdToken(IdTokenMixin, OpenIDCode):
            def exists_nonce(self, nonce, request): return False

        class TokenIdToken(IdTokenMixin, OpenIDToken):
            pass

        class CodeGrant(grants.AuthorizationCodeGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

            def save_authorization_code(self, code, request):
                p = request.payload
                idp._codes[code] = _AuthCode(code, request.client.get_client_id(), p.redirect_uri, p.scope,
                                             request.user, p.data)

            def query_authorization_code(self, code, client):
                ac = idp._codes.get(code)
                return ac if ac and ac.client_id == client.get_client_id() else None

            def delete_authorization_code(self, authorization_code): idp._codes.pop(authorization_code.code, None)
            def authenticate_user(self, authorization_code): return authorization_code.user

        class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

            def authenticate_user(self, username, password):
                return username if username in idp.users and idp.users[username] == password else None

        class RefreshGrant(grants.RefreshTokenGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = ["none"]
            INCLUDE_NEW_REFRESH_TOKEN = True

            def authenticate_refresh_token(self, refresh_token):
                rt = idp._refresh_tokens.get(refresh_token)
                return rt if rt and not rt.is_revoked() else None

            def authenticate_user(self, credential): return credential.user
            def revoke_old_credential(self, credential): credential.revoked = True

        # required=True: a public client cannot redeem a code without the right code_verifier
        self.server.register_grant(CodeGrant, [_CodeChallenge(required=True), CodeIdToken()])
        self.server.register_grant(PasswordGrant, [TokenIdToken()])
        self.server.register_grant(RefreshGrant, [TokenIdToken()])

    # ---- http -------------------------------------------------------------------------------
    def _add_routes(self):
        idp = self

        @self.app.get("/.well-known/openid-configuration")
        def discovery():
            return jsonify(
                issuer=idp.issuer,
                authorization_endpoint=f"{idp.issuer}/authorize",
                token_endpoint=f"{idp.issuer}/token",
                jwks_uri=f"{idp.issuer}/keys",
                response_types_supported=["code"],
                subject_types_supported=["public"],
                id_token_signing_alg_values_supported=["RS256"],
                scopes_supported=SCOPES,
                grant_types_supported=GRANT_TYPES,
                code_challenge_methods_supported=["S256"],
                token_endpoint_auth_methods_supported=["none"])

        @self.app.get("/keys")
        def keys():
            return jsonify(keys=[idp.key.as_dict(private=False)])

        @self.app.route("/authorize", methods=["GET", "POST"])
        def authorize():
            try:
                grant = idp.server.get_consent_grant(end_user=None)  # validates client, redirect_uri, scope, PKCE
            except OAuth2Error as e:
                return idp.server.handle_error_response(request, e)

            if request.method == "GET":
                return LOGIN_FORM

            login = request.form.get("login")
            if login not in idp.users or idp.users[login] != request.form.get("password"):
                return "bad credentials", 401
            return idp.server.create_authorization_response(grant_user=login, grant=grant)

        @self.app.post("/token")
        def token():
            return idp.server.create_token_response()
