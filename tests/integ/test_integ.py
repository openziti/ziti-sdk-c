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

def run_catch_test(test_tag, env, tmp_path):
    """Run the C++ Catch2 integration test binary."""
    log = open(tmp_path / f"{test_tag}-tests.log", "w")

    environment = os.environ.copy()
    environment.update(env)
    environment["ZITI_LOG"] = "5"
    proc = subprocess.Popen(
        [test_exe, "-s",
         "--reporter", f"JUnit::out={tmp_path}/TEST-{test_tag}.xml",
         "--reporter", "console::out=-",
         f"[{test_tag}]"],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=log,
        text=True,
        env=environment,
    )

    def _reader():
        for line in proc.stdout:
            logger.info("[integ-tests][%s] %s", test_tag, line.rstrip())

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    rc = proc.wait(timeout=300)
    t.join(timeout=5)
    assert rc == 0, f"[{test_tag}] exited with code {rc}"

@pytest.mark.parametrize("tag", ["basic","controller"])
def test_integ(enrolled_identities, tmp_path, request, tag):
    run_catch_test(tag, enrolled_identities, tmp_path)


def test_client(client_identity, echo_server, tmp_path):
    env = dict()
    env['test_client']=client_identity
    run_catch_test("connection", env, tmp_path)
