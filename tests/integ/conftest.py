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

import hashlib
import logging
import os
import shutil
import subprocess
import threading

import pytest

logger = logging.getLogger(__name__)


def ziti_edge(ziti_cli, *args, check=True):
    """Run a ``ziti edge`` subcommand."""
    result = subprocess.run(
        [ziti_cli, "edge"] + list(args),
        capture_output=True, text=True,
    )
    logger.info("ziti edge %s -> rc=%d", " ".join(args), result.returncode)
    if result.stdout:
        logger.info(result.stdout.rstrip())
    if result.stderr:
        logger.info(result.stderr.rstrip())
    if check and result.returncode != 0:
        pytest.fail(f"ziti edge {' '.join(args)} failed: {result.stderr}")
    return result


def compute_kid(cert_path):
    """Compute SHA-1 fingerprint of a DER-encoded certificate."""
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
        capture_output=True, check=True,
    )
    return hashlib.sha1(result.stdout).hexdigest()


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

ziti_executable = os.environ.get("ZITI_CLI", "ziti")
@pytest.fixture(scope="session")
def ziti_cli(tmp_path_factory):
    result = subprocess.run([ziti_executable, "version"], capture_output=True, text=True, check=True)
    logger.info("Using ziti CLI version: %s", result.stdout.strip())
    logger.info("tmp_path = %s", tmp_path_factory.getbasetemp())
    return ziti_executable


@pytest.fixture(scope="session")
def quickstart_home(tmp_path_factory):
    path = tmp_path_factory.mktemp("qs_root")
    os.makedirs(path, exist_ok=True)
    return path.__fspath__()


@pytest.fixture(scope="session")
def quickstart(ziti_cli, tmp_path_factory, quickstart_home):
    """Start ``ziti edge quickstart`` and wait for it to become ready."""

    proc = subprocess.Popen(
        [ziti_cli, "edge", "quickstart",
         "--home", quickstart_home,
         "--ctrl-address=127.0.0.1",
         "--router-address=127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    ready = threading.Event()

    def _reader():
        for line in proc.stdout:
            logger.info("[quickstart] %s", line.rstrip())
            if "controller and router started" in line:
                ready.set()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    if not ready.wait(timeout=300):
        proc.kill()
        pytest.fail("quickstart did not become ready within 300s")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@pytest.fixture(scope="session")
def base_model(quickstart, ziti_cli):
    ziti_edge(ziti_cli,
              "create", "service-policy", "servers-bind", "Bind",
              "--identity-roles", "#server",
              "--service-roles", "#all")

    ziti_edge(ziti_cli,
              "create", "service-policy", "clients-dial", "Dial",
              "--identity-roles", "#client",
              "--service-roles", "#all")

    ziti_edge(ziti_cli,
              "create", "service", "test-service")


@pytest.fixture(scope="session")
def ziti_model(ziti_cli, base_model, quickstart_home):
    """Create identities, service, and service policies."""
    ziti_edge(ziti_cli,
              "create", "identity", "test-client",
              "-a", "client",
              "-o", os.path.join(quickstart_home, "test-client.jwt"))

    ziti_edge(ziti_cli,
              "create", "identity", "test-server",
              "-a", "server",
              "-o", os.path.join(quickstart_home, "test-server.jwt"))


@pytest.fixture(scope="session")
def jwt_signers(ziti_model, ziti_cli, quickstart_home):
    """Generate JWT signing key/cert and create ext-jwt-signers."""
    key_path = os.path.join(quickstart_home, "test-jwt-signer.key")
    cert_path = os.path.join(quickstart_home, "test-jwt-signer.crt")
    kid_path = os.path.join(quickstart_home, "test-jwt-signer.kid")

    subprocess.run(
        ["openssl", "genrsa", "-out", key_path, "2048"],
        capture_output=True, check=True,
    )
    subprocess.run(
        ["openssl", "req", "-new", "-x509",
         "-key", key_path,
         "-out", cert_path,
         "-days", "365",
         "-subj", "/CN=test-jwt-signer/O=OpenZiti Test"],
        capture_output=True, check=True,
    )
    kid = compute_kid(cert_path)
    with open(kid_path, "w") as f:
        f.write(kid + "\n")
    logger.info("JWT signer kid: %s", kid)

    # enroll-to-cert signer
    ziti_edge(ziti_cli,
              "create", "ext-jwt-signer", "test-ext-jwt-signer",
              "https://test-jwt-issuer.example.com",
              "--cert-file", cert_path,
              "--audience", "openziti",
              "--enroll-to-cert",
              "--kid", kid)

    # enroll-to-token signer (same cert/kid — may fail if controller enforces
    # unique fingerprints; the original expect scripts silently ignored this)
    ziti_edge(ziti_cli,
              "create", "ext-jwt-signer", "test-ext-jwt-signer-token",
              "https://test-jwt-issuer-token.example.com",
              "--cert-file", cert_path,
              "--audience", "openziti",
              "--enroll-to-token",
              "--kid", kid,
              check=False)

    # keycloak not available
    with open(os.path.join(quickstart_home, "keycloak-available"), "w") as f:
        f.write("0\n")

    # pre-created identity for enroll-none tests
    ziti_edge(ziti_cli,
              "create", "identity", "test-precreated", "-a", "client")


@pytest.fixture(scope="session")
def enrolled_identities(jwt_signers, quickstart_home) -> dict[str, str]:
    """Enroll test-client and test-server identities."""
    enroller = os.environ.get("ENROLLER")
    if not enroller:
        pytest.skip("ENROLLER not set")

    ids = dict()
    for name in ("test-server", "test-client"):
        jwt_file = os.path.join(quickstart_home, f"{name}.jwt")
        json_file = os.path.join(quickstart_home, f"{name}.json")
        result = subprocess.run(
            [enroller, jwt_file, json_file],
            capture_output=True, text=True,
        )
        logger.info("[enroll %s] %s", name, result.stdout.rstrip())
        if "ziti identity is saved" not in result.stdout:
            pytest.fail(f"enrollment of {name} failed: {result.stderr}")
        ids[name] = json_file
    return ids
