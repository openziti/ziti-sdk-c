// Copyright (c) 2023. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ZITI_SDK_FIXTURES_H
#define ZITI_SDK_FIXTURES_H

#include <uv.h>
#include <cstdlib>

class LoopTestCase {
    uv_loop_t *m_loop;

protected:
    LoopTestCase():
                     m_loop(uv_loop_new())
    {}

    ~LoopTestCase() {
        int rc = uv_loop_close(loop());
        INFO("uv_loop_close() => " << uv_strerror(rc));
        CHECK(rc == 0);
        free(m_loop);
    }

    uv_loop_t *loop() { return m_loop; }
};
#endif // ZITI_SDK_FIXTURES_H
