// Copyright (c) 2026.  NetFoundry Inc
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.

//
//
#pragma once
#ifndef ZITI_SDK_JWT_H
#define ZITI_SDK_JWT_H

#include <stc/cstr.h>
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zt_jwt_s {
    cstr issuer;
    uint64_t expiration;
    json_object *claims;
    json_object *header;
    cstr encoded;
} zt_jwt;

extern void zt_jwt_drop(zt_jwt *jwt);
extern void zt_jwt_free(zt_jwt *jwt);
extern int zt_jwt_parse(const char *jwt_str, zt_jwt *jwt);

#ifdef __cplusplus
}
#endif
#endif // ZITI_SDK_JWT_H
