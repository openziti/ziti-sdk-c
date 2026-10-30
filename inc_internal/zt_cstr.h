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

//
//

#ifndef ZITI_SDK_ZT_CSTR_H
#define ZITI_SDK_ZT_CSTR_H

#include <ziti/model_support.h>

#ifdef __cplusplus
// stc/cstr.h declares _cstr_init as plain `extern`, which mangles under C++; common.h first, then cstr.h
// under C linkage
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}
#else
#include <stc/cstr.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

const type_meta* get_cstr_meta();

#ifdef __cplusplus
}
#endif

#endif // ZITI_SDK_ZT_CSTR_H
