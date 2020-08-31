/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * @file errors.h
 * @brief Defines the macros, functions, typedefs and constants pertaining to errors observed when using a Ziti Network
 */

#ifndef ZT_SDK_ERRORS_H

// @cond
#define ZT_SDK_ERRORS_H
// @endcond

#include "externs.h"
#include "error_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A helper macro to make declaring expected error conditions easier which is undef'ed immidately
 */
#define ERR_ID(e, _) ZITI_FUNC extern const int ZITI_##e;
ZITI_ERRORS(ERR_ID)
#undef ERR_ID

/**
* Returns a human-readable description for the provided code.
*/
ZITI_FUNC
extern const char *ziti_errorstr(int err);

#ifdef __cplusplus
}
#endif

#endif //ZT_SDK_ERRORS_H
