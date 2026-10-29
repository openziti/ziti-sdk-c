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


def test_mfa_enrolled(client_identity, tmp_path):
    env = dict()
    env['test_client']=client_identity['path']
    run_catch_test(env, tmp_path, tag="mfa-enrolled")


@pytest.mark.require_ziti('>=2.0.0')
def test_totp_token(client_identity, tmp_path):
    """The api session of a TOTP login has its TOTP token, and a code is taken after the login."""
    policy = "cert-totp-token"
    ziti_edge("create", "auth-policy", policy,
              "--primary-cert-allowed", "--secondary-req-totp")

    ziti_edge("update", "identity", client_identity['name'],
              "--auth-policy", policy)
    env = dict()
    env['test_client']=client_identity['path']
    run_catch_test(env, tmp_path, test="oidc-totp-token")


@pytest.mark.require_ziti('>=2.0.0')
def test_totp_enroll_after_login(client_identity, tmp_path):
    """An identity that logged in with its cert enrols MFA: the code of the enrollment buys the TOTP token."""
    env = dict()
    env['test_client']=client_identity['path']
    run_catch_test(env, tmp_path, test="oidc-totp-enroll-after-login")


@pytest.mark.require_ziti('>=2.0.0')
def test_totp_posture_check(client_identity, echo_server, test_service, tmp_path):
    """TOTP is part of the dial policy of a service (an MFA posture check) and not of the auth policy.

    The identity logs in with its cert alone and has no MFA, so the router turns the dial down. It enrols MFA after
    the login: the code of the enrollment is exchanged for a TOTP token, which is the proof the router takes, and the
    dial goes through. The next login of the (now enrolled) identity answers the TOTP prompt and dials too.
    GH-1061, GH-1170
    """
    name = test_service['name']
    posture_check = f"mfa-{name}"
    ziti_edge("create", "posture-check", "mfa", posture_check)

    # `clients-dial` of the base model lets every identity with the `client` role dial every service, with no
    # posture check: the identity leaves that role, and the policy with the check is its only way to the service
    ziti_edge("update", "identity", client_identity['name'], "--role-attributes", "mfa-client")
    ziti_edge("create", "service-policy", f"dial-{name}", "Dial",
              "--identity-roles", f"@{client_identity['name']}",
              "--service-roles", f"@{name}",
              "--posture-check-roles", f"@{posture_check}")

    env = dict()
    env['test_client'] = client_identity['path']
    env['test_service'] = name
    run_catch_test(env, tmp_path, test="oidc-totp-posture-check")


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


@pytest.mark.require_ziti('>=2.0.0')
def test_secondary_ext_jwt_issuer_is_not_the_signer_url(secondary_ext_jwt, idp, idp_signer, tmp_path):
    """The signer says its IdP is somewhere else than the issuer of the tokens, so the SDK cannot tell whose token is whose.

    It must carry on as before and not wait for a login that it already has the token for. GH-1159
    """
    ziti_edge("update", "ext-jwt-signer", idp_signer, "--external-auth-url", f"{idp.issuer}/elsewhere")
    try:
        run_catch_test(secondary_ext_jwt, tmp_path, test="oidc-secondary-ext-jwt")
    finally:
        ziti_edge("update", "ext-jwt-signer", idp_signer, "--external-auth-url", idp.issuer)


@pytest.mark.require_ziti('>=2.0.0')
@pytest.mark.parametrize("variant", ["", "-answered-in-event", "-answered-with-expired", "-other-issuer", "-login-restarted",
                                     "-refreshed"])
def test_secondary_ext_jwt_expired(variant, secondary_ext_jwt, idp, idp_user, tmp_path):
    """The secondary token expires and nothing replaces it, as when the IdP session ended.

    The context has to ask for the external login again, not carry on as authenticated and re-authenticate
    in a loop, and a new token completes the authentication. GH-1159

    Variants: the app answers from inside the event that asks (with a valid token, and with the expired one every
    time), a token of another issuer arrives meanwhile, the auth method starts its login over and the
    controller asks for a TOTP, and the api session token is refreshed during the wait.
    """
    env = dict(secondary_ext_jwt)
    env['IDP_TOKEN'] = idp.access_token(idp_user, ttl=4)
    env['IDP_TOKEN_NEXT'] = idp.access_token(idp_user)
    env['IDP_TOKEN_OTHER_ISSUER'] = idp.token_of_other_issuer(idp_user)
    run_catch_test(env, tmp_path, test=f"oidc-secondary-ext-jwt-expired{variant}")


@pytest.mark.require_ziti('>=2.0.0')
@pytest.mark.parametrize("variant", ["", "-answered-with-rejected", "-refreshed", "-late-unauthorized"])
def test_secondary_ext_jwt_rejected(variant, secondary_ext_jwt, idp, idp_user, tmp_path):
    """The controller turns down the secondary token although it has not expired, here for its signature.

    The context has to find out from the controller that the token is what it wants, ask for the external login
    and wait for it, not re-authenticate in a loop, and a new token completes the authentication. GH-1159

    Variants: the app answers every request for the login with the token that was turned down, the auth method
    refreshes the api session token during the wait, and a refresh finds out about the rejected token (a 401 from a
    request sent before the wait then arrives during it).
    """
    env = dict(secondary_ext_jwt)
    env['IDP_TOKEN_NEXT'] = idp.access_token(idp_user)
    env['IDP_TOKEN_BAD_SIGNATURE'] = idp.token_with_bad_signature(idp_user)
    run_catch_test(env, tmp_path, test=f"oidc-secondary-ext-jwt-rejected{variant}")


@pytest.mark.require_ziti('>=2.0.0')
def test_secondary_ext_jwt_issuer_differs(secondary_ext_jwt, idp, idp_signer, idp_user, tmp_path):
    """The signer says its IdP is somewhere else than the issuer of its tokens, and the controller turns a token down.

    The SDK cannot tell whose token is whose, so it says so once and lets the controller decide: the token that
    completes the login is accepted although its issuer is not the one the SDK has for the signer. GH-1159
    """
    env = dict(secondary_ext_jwt)
    env['IDP_TOKEN_NEXT'] = idp.access_token(idp_user)
    env['IDP_TOKEN_BAD_SIGNATURE'] = idp.token_with_bad_signature(idp_user)

    ziti_edge("update", "ext-jwt-signer", idp_signer, "--external-auth-url", f"{idp.issuer}/elsewhere")
    try:
        run_catch_test(env, tmp_path, test="oidc-secondary-ext-jwt-issuer-differs")
    finally:
        ziti_edge("update", "ext-jwt-signer", idp_signer, "--external-auth-url", idp.issuer)


@pytest.mark.require_ziti('>=2.0.0')
def test_secondary_ext_jwt_url_with_trailing_slash(secondary_ext_jwt, idp, idp_signer, idp_user, tmp_path):
    """The URL of the signer has a trailing slash that the issuer of its tokens has not: the same issuer.

    ``oidc-secondary-ext-jwt-rejected`` checks that the SDK has nothing to say about the issuer of the tokens. GH-1159
    """
    env = dict(secondary_ext_jwt)
    env['IDP_TOKEN_NEXT'] = idp.access_token(idp_user)
    env['IDP_TOKEN_BAD_SIGNATURE'] = idp.token_with_bad_signature(idp_user)

    ziti_edge("update", "ext-jwt-signer", idp_signer, "--external-auth-url", f"{idp.issuer}/")
    try:
        run_catch_test(env, tmp_path, test="oidc-secondary-ext-jwt-rejected")
    finally:
        ziti_edge("update", "ext-jwt-signer", idp_signer, "--external-auth-url", idp.issuer)


@pytest.mark.require_ziti('>=2.0.0')
def test_secondary_ext_jwt_session_lost(secondary_ext_jwt, tmp_path):
    """The controller turns down the api session of the context, not the secondary token.

    It lists no external login for the context then, and the context authenticates again as it did before it
    asked the controller. GH-1159
    """
    run_catch_test(secondary_ext_jwt, tmp_path, test="oidc-secondary-ext-jwt-session-lost")
