// Copyright (c) 2022.  NetFoundry Inc.
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


#ifndef ZITI_SDK_TYPES_H
#define ZITI_SDK_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "externs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int64_t duration;

ZITI_FUNC int parse_duration(duration *val, const char* str, size_t len);


#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_TYPES_H
