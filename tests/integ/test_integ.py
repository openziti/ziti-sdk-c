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
#

import logging
import os
import subprocess
import threading
import pytest

logger = logging.getLogger(__name__)
test_exe = os.environ.get("TEST_EXE")

def run_catch_test(env, tmp_path, tag="", test="", ):
    """Run the C++ Catch2 integration test binary."""
    if not test_exe:
        pytest.fail("TEST_EXE environment variable is not set")

    if test:
        spec = test
    elif tag:
        spec = f"[{tag}]"
    else:
        pytest.skip("test spec is missing")

    filename = spec.strip("[]").replace(" ", "_")

    log = open(tmp_path / f"{filename}.log", "w")

    environment = os.environ.copy()
    environment.update(env)
    environment["ZITI_LOG"] = "5"
    proc = subprocess.Popen(
        [test_exe, "-s",
         "--reporter", f"JUnit::out={tmp_path}/TEST-{filename}.xml",
         "--reporter", "console::out=-",
         spec],
        stdout=subprocess.PIPE,
        stderr=log,
        text=True,
        env=environment,
    )

    def _reader():
        for line in proc.stdout:
            logger.info("[test](%s) %s", spec, line.rstrip())

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    try:
        rc = proc.wait(timeout=300)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail(f"({spec}) timed out after 5 minutes")

    t.join(timeout=5)
    assert rc == 0, f"({spec}) exited with code {rc}"

def test_basic(tmp_path):
    run_catch_test({}, tmp_path, "basic")

@pytest.mark.parametrize("tag", ["auth","controller"])
def test_identity(enrolled_identities, tmp_path, tag):
    run_catch_test(enrolled_identities, tmp_path, tag)


def test_connect(client_identity, echo_server, test_service, tmp_path):
    env = dict()
    env['test_client']=client_identity['path']
    env['test_service']=test_service['name']
    run_catch_test(env, tmp_path, "connection")


def test_zitilib(client_identity, tmp_path):
    env = dict()
    env['test_client']=client_identity['path']
    run_catch_test(env, tmp_path, "zitilib")


def test_zitilib_connect(client_identity, test_service, echo_server, tmp_path):
    env = dict()
    env['test_client']=client_identity['path']
    env['test_service']=test_service['name']
    env['test_intercept']=test_service['intercept']
    run_catch_test(env, tmp_path, "zl-connect")
