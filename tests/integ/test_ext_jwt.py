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

"""The ``idp_signer`` setup against the quickstart controller, without the SDK.

An ``ext-jwt-signer`` trusting the in-process OIDC provider (``oidc_idp.py``) is the starting point of
every external JWT login. These tests make the controller do what the SDK asks of it
(``library/oidc.c``: ``/oidc/login/ext-jwt``, ``library/external_auth.c``: ``/enroll/token``), with a
token from the idp, so that a failing SDK test can tell a harness problem from an SDK problem.
"""

import base64
import hashlib
import json
import secrets
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

import pytest

from conftest import IDP_CLIENT_ID, ziti_edge

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
