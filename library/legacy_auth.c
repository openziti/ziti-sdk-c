// Copyright (c) 2023-2024. NetFoundry Inc.
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

#include "auth_method.h"
#include "zt_internal.h"

struct legacy_auth_s {
    ziti_auth_method_t api;
};

static int legacy_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx);
static int legacy_auth_stop(ziti_auth_method_t *self);
static void legacy_auth_free(ziti_auth_method_t *self);

#define LEGACY_AUTH_INIT()          \
    (ziti_auth_method_t) {          \
        .kind = LEGACY,             \
        .start = legacy_auth_start, \
        .stop = legacy_auth_stop,   \
        .free = legacy_auth_free,   \
    }

ziti_auth_method_t *new_legacy_auth(ziti_controller *ctrl) {
    struct legacy_auth_s *auth = calloc(1, sizeof(*auth));
    auth->api = LEGACY_AUTH_INIT();
    return &auth->api;
}

int legacy_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
}

int legacy_auth_stop(ziti_auth_method_t *self) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    return ZITI_OK;
}

void legacy_auth_free(ziti_auth_method_t *self) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);

    free(auth);
}
