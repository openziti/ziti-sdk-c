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
import json
import re

import pytest

from test_integ import run_catch_test
from conftest import ziti_edge

@pytest.mark.require_ziti('>=2.0.0')
def test_totp_auth(client_identity, tmp_path):
    policy = "cert-totp"
    ziti_edge("create", "auth-policy", policy,
              "--primary-cert-allowed", "--secondary-req-totp")

    ziti_edge("update", "identity", client_identity['name'],
              "--auth-policy", policy)
    env = dict()
    env['test_client']=client_identity['path']
    run_catch_test(env, tmp_path, test="oidc-totp")


@pytest.fixture
def secondary_ext_jwt(idp, idp_signer, idp_user, client_identity, request):
    """Environment of a Catch test for an identity that logs in with its cert and needs a token as secondary auth.

    The auth policy of the identity requires ``idp_signer`` for that token: ``test_client`` is the identity
    and ``IDP_TOKEN`` the token of the idp user whose email is the external id of the identity.
    """
    # the policy takes the id of the signer, not its name
    signers = ziti_edge("list", "ext-jwt-signers", f'name = "{idp_signer}"', "-j").stdout
    signer_id = json.loads(signers)["data"][0]["id"]

    policy = "cert-ext-jwt-secondary-" + re.sub(r"\W+", "-", request.node.name).strip("-")
    ziti_edge("create", "auth-policy", policy,
              "--primary-cert-allowed", "--secondary-req-ext-jwt-signer", signer_id)

    # the controller matches the sub of the token (the email) with the external id of the identity
    ziti_edge("update", "identity", client_identity['name'],
              "--auth-policy", policy, "--external-id", idp_user)

    return {
        'test_client': client_identity['path'],
        'IDP_TOKEN': idp.password_grant(idp_user)["access_token"],
    }


@pytest.mark.require_ziti('>=2.0.0')
@pytest.mark.parametrize("method", ["oidc", "legacy"])
def test_secondary_ext_jwt(secondary_ext_jwt, tmp_path, method):
    """Cert as primary auth, a token from an ext-jwt-signer as secondary auth: ``<method>-secondary-ext-jwt``.

    The controller answers the cert login with an EXT-JWT auth query. With OIDC (oidc-tests.cpp) it takes the
    token as a bearer on the login again, with the legacy method (legacy-auth.cpp) as a bearer on the
    requests of that api session. GH-919
    """
    run_catch_test(secondary_ext_jwt, tmp_path, test=f"{method}-secondary-ext-jwt")


@pytest.mark.require_ziti('>=2.0.0')
@pytest.mark.parametrize("method", ["oidc", "legacy"])
def test_secondary_ext_jwt_rotation(secondary_ext_jwt, idp, idp_user, tmp_path, method):
    """The secondary token the identity logged in with expires and its refreshed token takes its place.

    ``IDP_TOKEN`` is short-lived and ``IDP_TOKEN_NEXT`` is what the external login hands over before that:
    the controller checks the token of every request, so only the new one may be sent. GH-1158
    """
    env = dict(secondary_ext_jwt)
    env['IDP_TOKEN'] = idp.access_token(idp_user, ttl=4)
    env['IDP_TOKEN_NEXT'] = idp.access_token(idp_user)
    run_catch_test(env, tmp_path, test=f"{method}-secondary-ext-jwt-rotation")

