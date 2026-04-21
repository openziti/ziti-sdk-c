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

import logging
import os
import subprocess
import threading
import pytest

from pip._internal.utils import temp_dir

logger = logging.getLogger(__name__)

@pytest.mark.parametrize("tag", ["basic","controller"])
def test_integ(enrolled_identities, tmp_path, request, tag):
    """Run the C++ Catch2 integration test binary."""
    log = open(tmp_path / f"{tag}-tests.log", "w")

    test_exe = os.environ["TEST_EXE"]
    env = enrolled_identities.copy()
    env["ZITI_LOG"] = "5"
    proc = subprocess.Popen(
        [test_exe, "--reporter", f"JUnit::out={tmp_path}/{tag}-tests.xml", "--reporter", "console::out=-", f"[{tag}]"],
        stdout=subprocess.PIPE,
        stderr=log,
        text=True,
        env=env,
    )

    def _reader():
        for line in proc.stdout:
            logger.info("[integ-tests] %s", line.rstrip())

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    rc = proc.wait(timeout=300)
    t.join(timeout=5)
    assert rc == 0, f"integ-tests exited with code {rc}"
