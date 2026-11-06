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

"""External JWT enrollment with the GitHub Actions token of the job that runs the tests.

This is what a workflow does to get onto a Ziti network without an identity in its secrets: it asks
GitHub for an OIDC token, and a signer that trusts GitHub (``enroll-to-token``) creates the identity of
the repository on the first login. The tokens only exist inside a job with ``id-token: write``, so
everywhere else (a laptop, a pull request from a fork) these tests skip; ``test_ext_jwt.py`` covers the
same controller and SDK paths with tokens of the in-process idp.

The SDK is handed the token the way an app that holds it already does it, without selecting a signer
(``ztx-enroll-token-direct-lifecycle`` in enroll_mode_tests.cpp): the signer needs no IdP url and no client id.
"""

import base64
import json
import os
import urllib.parse
import urllib.request

import pytest

from conftest import ziti_edge
from test_ext_jwt import zitilib_env
from test_integ import run_catch_test

pytestmark = [
    pytest.mark.require_ziti('>=2.0.0'),
    pytest.mark.skipif(not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"),
                       reason="not a GitHub Actions job that has `id-token: write`"),
]

GH_ISSUER = "https://token.actions.githubusercontent.com"
GH_AUDIENCE = "ziti-sdk-c-ci"
GH_SIGNER = "github-actions-signer"


def _get_json(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=30) as resp:
        return json.load(resp)


def github_token():
    """A token of this job for ``GH_AUDIENCE``. They do not live long, so ask right before it is used."""
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + urllib.parse.quote(GH_AUDIENCE)
    bearer = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    return _get_json(url, {"Authorization": f"bearer {bearer}"})["value"]


def jwt_claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def identities_of(external_id):
    out = ziti_edge("list", "identities", f'externalId = "{external_id}"', "-j").stdout
    return json.loads(out)["data"]


@pytest.fixture(scope="session")
def github_signer(ziti_model):
    """Name of the ext-jwt-signer that trusts GitHub, names an identity after the repository and enrolls it to a token."""
    jwks = _get_json(f"{GH_ISSUER}/.well-known/openid-configuration")["jwks_uri"]

    # GitHub has no login to start, and the SDK selects no signer: no IdP url, no client id
    ziti_edge("create", "ext-jwt-signer", GH_SIGNER, GH_ISSUER,
              "--jwks-endpoint", jwks,
              "--audience", GH_AUDIENCE,
              "--claims-property", "repository",
              "--enroll-to-token",
              "--enroll-name-claims-selector", "/repository")
    return GH_SIGNER


@pytest.fixture
def github_login(github_signer):
    """``(token, repository)``: a token of this job for ``github_signer``, and the repository it names.

    The first login with the token enrolls the identity of the repository. It goes when the test is done,
    so that the next test enrolls it again instead of logging in to an existing one.
    """
    token = github_token()
    repository = jwt_claims(token)["repository"]
    yield token, repository
    ziti_edge("delete", "identity", "where", f'externalId = "{repository}"', check=False)


def test_sdk_enrolls_to_token_with_github_token(client_identity, github_login, tmp_path):
    """The first login with the token creates the identity of the repository.

    ``client_identity`` only provides the controller's address and CA, the way a bootstrap config would.
    """
    token, repository = github_login
    assert not identities_of(repository), "nothing could have enrolled this repository yet"

    env = {"test_client": client_identity["path"], "IDP_TOKEN": token}
    run_catch_test(env, tmp_path, test="ztx-enroll-token-direct-lifecycle")

    created = identities_of(repository)
    assert [i["name"] for i in created] == [repository]


def test_zitilib_enrolls_to_token_with_github_token(github_login, tmp_path):
    """The zitilib calls of an app that holds the token, as a Python hook makes them: ``zl-enroll-token-login``.

    The token is all the app has, the controller's network JWT its trust anchor: it enrolls, loads the
    identity it gets and logs in to it with the same token.
    """
    token, repository = github_login
    assert not identities_of(repository), "nothing could have enrolled this repository yet"

    run_catch_test(zitilib_env(token), tmp_path, test="zl-enroll-token-login")

    created = identities_of(repository)
    assert [i["name"] for i in created] == [repository]
