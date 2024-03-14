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

#ifndef ZITI_SDK_AUTH_METHOD_H
#define ZITI_SDK_AUTH_METHOD_H

#include "ziti_ctrl.h"

enum AuthenticationMethod {
    LEGACY,
    HA
};

typedef enum {
    ZitiAuthStateUnauthenticated,
    ZitiAuthStateAuthStarted,

    ZitiAuthStatePartiallyAuthenticated,
    ZitiAuthStateFullyAuthenticated,

    ZitiAuthImpossibleToAuthenticate,
} ziti_auth_state;

typedef struct ziti_ctx *ziti_context;
typedef struct ziti_auth_method_s ziti_auth_method_t;
typedef void (*auth_state_cb)(void *ctx, ziti_auth_state, const void *data);

struct ziti_auth_method_s {
    enum AuthenticationMethod kind;
    int (*start)(ziti_auth_method_t *self, auth_state_cb cb, void *ctx);
    int (*submit_mfa)(ziti_auth_method_t *self, const char *code);
    int (*stop)(ziti_auth_method_t *self);
    void (*free)(ziti_auth_method_t *self);
};

ziti_auth_method_t *new_legacy_auth(ziti_controller *ctrl);
ziti_auth_method_t *new_ha_auth(ziti_context ztx);

#endif // ZITI_SDK_AUTH_METHOD_H
