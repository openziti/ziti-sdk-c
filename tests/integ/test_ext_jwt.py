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

"""External JWT login with tokens from the in-process OIDC provider (``oidc_idp.py``).

An ``ext-jwt-signer`` trusting that provider (``idp_signer``) is the starting point of every external
JWT login. The first tests make the controller do what the SDK asks of it (``library/oidc.c``:
``/oidc/login/ext-jwt``, ``library/external_auth.c``: ``/enroll/token``), with a token from the idp and
no SDK involved, so that a failing SDK test can tell a harness problem from an SDK problem. The last
one runs the SDK itself, in each enroll mode.
"""

import base64
import hashlib
import json
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from conftest import IDP_CLIENT_ID, ziti_edge
from test_integ import run_catch_test

pytestmark = pytest.mark.require_ziti('>=2.0.0')

# the ``quickstart`` fixture lets ziti pick its default port
CTRL_URL = "https://127.0.0.1:1280"
# only the SDK's loopback listener is behind this, which is not running here
CALLBACK_URL = "http://localhost:20314/auth/callback"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# the controller's certificate is not signed by anything this python trusts; it is our own, on loopback
_tls = ssl.create_default_context()
_tls.check_hostname = False
_tls.verify_mode = ssl.CERT_NONE
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                      urllib.request.HTTPSHandler(context=_tls))


def _request(method, url, *, headers=None, body=None, form=None):
    """Returns ``(status, headers, text)``; redirects are returned, not followed."""
    headers = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _opener.open(req, timeout=10) as resp:
            return resp.status, resp.headers, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def _request_to_loopback(url):
    """``GET`` an url of ``localhost``, on whichever loopback address something listens.

    The SDK's login listener is on the IPv6 loopback, and a browser tries every address of ``localhost``.
    This resolver does not: where ``/etc/hosts`` has ``localhost`` for ``127.0.0.1`` only (Ubuntu's default),
    ``localhost`` would never get there.
    """
    parts = urllib.parse.urlsplit(url)
    failure = None
    for host in ("[::1]", "127.0.0.1"):
        try:
            return _request("GET", parts._replace(netloc=f"{host}:{parts.port}").geturl())
        except OSError as e:  # nothing listens there
            failure = e
    raise failure


def ctrl_login(token):
    """Log in to the controller's OIDC provider with an external jwt, the way ``library/oidc.c`` does.

    Returns ``(200, token response)`` or the status of the step that failed and its body.
    """
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({
        "client_id": "openziti", "scope": "openid offline_access", "response_type": "code",
        "redirect_uri": CALLBACK_URL, "code_challenge": challenge, "code_challenge_method": "S256",
        "state": "state", "audience": "openziti"})

    status, headers, text = _request("POST", f"{CTRL_URL}/oidc/authorize?{query}")
    assert status == 302, text
    auth_id = urllib.parse.parse_qs(urllib.parse.urlparse(headers["Location"]).query)["authRequestID"][0]

    status, headers, text = _request("POST", f"{CTRL_URL}/oidc/login/ext-jwt?id={auth_id}",
                                     headers={"Authorization": f"Bearer {token}"},
                                     body={"sdkInfo": {"type": "ziti-integ-test"}})
    if status != 302:
        return status, text

    status, headers, text = _request("GET", headers["Location"])
    assert status == 302 and headers["Location"].startswith(CALLBACK_URL), text
    code = urllib.parse.parse_qs(urllib.parse.urlparse(headers["Location"]).query)["code"][0]

    status, _, text = _request("POST", f"{CTRL_URL}/oidc/oauth/token", form={
        "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
        "client_id": "openziti", "redirect_uri": CALLBACK_URL})
    return status, json.loads(text)


def enroll_with_token(token, csr=None):
    """``POST /enroll/token`` as ``ziti_ctrl_enroll_token`` does: returns ``(status, body)``."""
    status, _, text = _request("POST", f"{CTRL_URL}/edge/client/v1/enroll/token",
                               headers={"Authorization": f"Bearer {token}"},
                               body={"clientCsr": csr} if csr else {})
    return status, json.loads(text)


def create_csr(path):
    key, csr = path / "enroll.key", path / "enroll.csr"
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(csr), "-subj", "/O=OpenZiti/CN=enrollToCert"],
                   capture_output=True, check=True)
    return csr.read_text()


def identity_exists(external_id):
    return external_id in ziti_edge("list", "identities", f'externalId = "{external_id}"').stdout


def network_jwt():
    """What an app that does not trust the controller yet verifies it with: ``zl-enroll-token-login`` needs it."""
    status, _, text = _request("GET", f"{CTRL_URL}/network-jwts")
    assert status == 200, text
    return json.loads(text)["data"][0]["token"]


def zitilib_env(token):
    """What the zitilib cases of an app that holds a token (``zl-enroll-*-login``) are given."""
    return {"NETWORK_JWT": network_jwt(), "IDP_TOKEN": token}


def start_browser(idp, user, url_file):
    """Plays the user of an interactive login: takes the login url the SDK writes to ``url_file``, logs in at
    the idp and delivers the redirect to the SDK's local listener.

    Returns ``(thread, delivered)``: join the thread, then check ``delivered`` (``error``, or the ``status``
    the listener answered with).
    """
    delivered = {}

    def browser():
        try:
            deadline = time.monotonic() + 30
            while not url_file.exists():
                assert time.monotonic() < deadline, "the SDK gave out no login url"
                time.sleep(0.05)
            redirect = idp.login(url_file.read_text().strip(), user)
            delivered["status"], _, delivered["text"] = _request_to_loopback(redirect)
        except BaseException as e:  # reported by the test, this is not its thread
            delivered["error"] = e

    thread = threading.Thread(target=browser, daemon=True)
    thread.start()
    return thread, delivered


def test_signer_is_listed(idp, idp_signer):
    """What the SDK reads in ``ziti_get_ext_jwt_signers`` to find the idp and how to talk to it."""
    status, _, text = _request("GET", f"{CTRL_URL}/edge/client/v1/external-jwt-signers")
    assert status == 200, text
    signer = next(s for s in json.loads(text)["data"] if s["name"] == idp_signer)

    assert signer["externalAuthUrl"] == idp.issuer
    assert signer["clientId"] == IDP_CLIENT_ID
    assert signer["audience"] == IDP_CLIENT_ID
    assert signer["targetToken"] == "ACCESS"


@pytest.mark.parametrize("token_type", ["access_token", "id_token"])
def test_login_to_precreated_identity(idp, idp_signer, idp_user, token_type):
    """``enroll none``: the identity exists already, and its external id is the ``sub`` of the token."""
    ziti_edge("create", "identity", idp_user, "--external-id", idp_user, "-a", "client")

    status, resp = ctrl_login(idp.password_grant(idp_user)[token_type])
    assert status == 200, resp
    assert resp["access_token"]


def test_login_of_unknown_identity_is_rejected(idp, idp_signer, idp_user):
    status, resp = ctrl_login(idp.password_grant(idp_user)["access_token"])
    assert status == 401, resp
    assert not identity_exists(idp_user)


def test_enroll_to_token(idp, idp_signer, idp_user, enroll_mode):
    """``enroll token``: the identity is created on the first token and is then logged in as usual."""
    enroll_mode("token")
    token = idp.password_grant(idp_user)["access_token"]

    status, resp = enroll_with_token(token)
    assert status == 200, resp
    assert identity_exists(idp_user)

    status, resp = ctrl_login(token)
    assert status == 200, resp


def test_enroll_to_cert(idp, idp_signer, idp_user, enroll_mode, tmp_path):
    """``enroll cert``: the controller signs the CSR that comes with the first token."""
    enroll_mode("cert")

    status, resp = enroll_with_token(idp.password_grant(idp_user)["access_token"], create_csr(tmp_path))
    assert status == 200, resp
    assert "BEGIN CERTIFICATE" in resp["data"]["cert"]
    assert identity_exists(idp_user)


@pytest.mark.parametrize("mode", ["cert", "token", "none"])
def test_sdk_login_per_enroll_mode(idp, idp_signer, idp_user, enroll_mode, client_identity, tmp_path, mode):
    """The SDK logs in with a token from the idp: ``ztx-enroll-<mode>-lifecycle`` in enroll_mode_tests.cpp.

    ``client_identity`` only provides the controller's address and CA, the way a bootstrap config would.
    """
    enroll_mode(mode)
    if mode == "none":
        # nothing creates the identity for the SDK to log in to
        ziti_edge("create", "identity", idp_user, "--external-id", idp_user, "-a", "client")

    env = {
        "test_client": client_identity["path"],
        "IDP_SIGNER": idp_signer,
        "IDP_TOKEN": idp.password_grant(idp_user)["access_token"],
    }
    run_catch_test(env, tmp_path, test=f"ztx-enroll-{mode}-lifecycle")


def test_zitilib_enroll_to_token_and_login(idp, idp_signer, idp_user, enroll_mode, tmp_path):
    """An app that holds the token enrolls and logs in through zitilib: ``zl-enroll-token-login`` in zitilib_tests.cpp.

    No identity of the app is involved: the token is all it has, the controller's network JWT its trust anchor.
    """
    enroll_mode("token")
    env = zitilib_env(idp.password_grant(idp_user)["access_token"])
    run_catch_test(env, tmp_path, test="zl-enroll-token-login")
    assert identity_exists(idp_user)


def test_zitilib_enroll_to_cert_and_login(idp, idp_signer, idp_user, enroll_mode, tmp_path):
    """The same through a signer that enrolls to a cert: ``zl-enroll-cert-login`` in zitilib_tests.cpp."""
    enroll_mode("cert")
    env = zitilib_env(idp.password_grant(idp_user)["access_token"])
    run_catch_test(env, tmp_path, test="zl-enroll-cert-login")
    assert identity_exists(idp_user)


def test_zitilib_enroll_none_bootstraps_from_network_jwt(ziti_model, tmp_path):
    """No idp in mode none: ``zl-enroll-none-bootstrap`` in zitilib_tests.cpp."""
    run_catch_test({"NETWORK_JWT": network_jwt()}, tmp_path, test="zl-enroll-none-bootstrap")


def test_zitilib_enroll_with_unknown_signer_name(idp, idp_signer, enroll_mode, tmp_path):
    """A signer name the controller does not have: ``zl-enroll-unknown-signer`` in zitilib_tests.cpp."""
    enroll_mode("token")
    run_catch_test({"NETWORK_JWT": network_jwt()}, tmp_path, test="zl-enroll-unknown-signer")


def test_zitilib_enroll_interactive(idp, idp_signer, idp_user, enroll_mode, tmp_path):
    """A login with a signer is interactive: ``zl-enroll-interactive`` in zitilib_tests.cpp.

    This plays the browser: it takes the login url the SDK gives out, logs in at the idp, and delivers the
    redirect to the SDK's local listener.
    """
    enroll_mode("token")
    url_file = tmp_path / "login-url"
    env = {"NETWORK_JWT": network_jwt(), "IDP_SIGNER": idp_signer, "LOGIN_URL_FILE": str(url_file)}

    thread, delivered = start_browser(idp, idp_user, url_file)
    try:
        run_catch_test(env, tmp_path, test="zl-enroll-interactive")
    finally:
        thread.join(timeout=10)

    assert "error" not in delivered, delivered.get("error")
    assert delivered.get("status") == 200, delivered
    assert identity_exists(idp_user)


def test_zitilib_enroll_interactive_cancel(idp, idp_signer, enroll_mode, tmp_path):
    """A pending enrollment times out, is one at a time and can be abandoned: ``zl-enroll-interactive-cancel``."""
    enroll_mode("token")
    run_catch_test({"NETWORK_JWT": network_jwt(), "IDP_SIGNER": idp_signer}, tmp_path,
                   test="zl-enroll-interactive-cancel")


def test_zitilib_login_external(idp, idp_signer, idp_user, enroll_mode, tmp_path):
    """An identity of the idp's user is logged in through zitilib: ``zl-login-external`` in zitilib_tests.cpp.

    The identity exists already (``enroll none``), and the app has only the controller's address and CA:
    ``Ziti_login_external`` gives it the url, and this plays the browser at that url.
    """
    enroll_mode("none")
    ziti_edge("create", "identity", idp_user, "--external-id", idp_user, "-a", "client")
    url_file = tmp_path / "login-url"
    env = {"NETWORK_JWT": network_jwt(), "IDP_SIGNER": idp_signer, "LOGIN_URL_FILE": str(url_file)}

    thread, delivered = start_browser(idp, idp_user, url_file)
    try:
        run_catch_test(env, tmp_path, test="zl-login-external")
    finally:
        thread.join(timeout=10)

    assert "error" not in delivered, delivered.get("error")
    assert delivered.get("status") == 200, delivered


@pytest.fixture
def silent_idp():
    """Url of an idp that takes every connection and never answers it."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(0.2)
    held, stop = [], threading.Event()

    def accept():
        while not stop.is_set():
            try:
                held.append(server.accept()[0])
            except OSError:  # nobody came
                pass

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.getsockname()[1]}"
    stop.set()
    thread.join(timeout=5)
    for conn in held:
        conn.close()
    server.close()


@pytest.fixture(params=["refused", "silent"])
def idp_down_signer(ziti_model, request):
    """Name of an ext-jwt-signer whose idp does not answer: nothing listens at its address (the port is reserved),
    or the idp takes the connection and says nothing."""
    name = "integration-test-idp-down"
    down = "http://127.0.0.1:1" if request.param == "refused" else request.getfixturevalue("silent_idp")
    ziti_edge("create", "ext-jwt-signer", name, down,
              "--jwks-endpoint", f"{down}/keys",
              "--external-auth-url", down,
              "--client-id", IDP_CLIENT_ID,
              "--audience", IDP_CLIENT_ID)
    yield name
    ziti_edge("delete", "ext-jwt-signer", name, check=False)


def test_zitilib_login_external_idp_down(idp_down_signer, tmp_path):
    """The idp of the signer does not answer: ``zl-login-external-idp-down`` in zitilib_tests.cpp."""
    run_catch_test({"NETWORK_JWT": network_jwt(), "IDP_SIGNER": idp_down_signer}, tmp_path,
                   test="zl-login-external-idp-down")


def test_sdk_enroll_cert_with_key_from_callback(idp, idp_signer, idp_user, enroll_mode, client_identity, tmp_path):
    """``ztx-enroll-cert-key-cb-lifecycle``: ``enroll_key_cb`` returns a ``keychain:`` key reference, not PEM."""
    enroll_mode("cert")

    env = {
        "test_client": client_identity["path"],
        "IDP_SIGNER": idp_signer,
        "IDP_TOKEN": idp.password_grant(idp_user)["access_token"],
    }
    run_catch_test(env, tmp_path, test="ztx-enroll-cert-key-cb-lifecycle")
