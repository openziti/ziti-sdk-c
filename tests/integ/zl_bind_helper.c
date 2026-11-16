// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Pure-C shim for zl_bind_tests.cpp: what it looks at is inside the context of a zitilib handle, which belongs to the
// thread of the loop of zitilib, so it is looked at from there (like ztx_test_helper.c, this is C because zt_internal.h is).

#include "zitilib/zl.h"
#include "zt_internal.h"
#include "connect.h"

struct open_server_conns_req {
    ziti_handle_t handle;
    int open;
};

static void open_server_conns_work(void *arg, future_t *f, uv_loop_t *l) {
    struct open_server_conns_req *req = arg;
    ztx_wrap_t *wrap = zl_find_wrap(req->handle);
    if (wrap == NULL) {
        fail_future(f, EINVAL);
        return;
    }

    uint32_t id;
    ziti_connection conn;
    MODEL_MAP_FOREACH(id, conn, &wrap->ztx->connections) {
        req->open += conn->type == Server && !conn->close;
    }
    complete_future(f, NULL, 0);
}

// how many server connections the context of the zitilib handle has that were not closed (-1: no such context)
int zl_test_open_server_conns(ziti_handle_t handle) {
    struct open_server_conns_req req = {.handle = handle};
    future_t *f = schedule_on_loop(open_server_conns_work, &req, true);
    int rc = await_future(f, NULL);
    destroy_future(f);
    return rc ? -1 : req.open;
}
