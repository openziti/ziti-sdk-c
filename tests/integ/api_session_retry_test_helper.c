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

// Pure-C shim so api_session_retry_tests.cpp (a C++ TU) never has to
// #include zt_internal.h itself. zt_internal.h pulls in <stc/cstr.h>, whose
// _cstr_init/_cstr_internal_move are unconditionally `extern` (not gated by
// STC's own i_header/i_static linkage macros) while the same header also
// pulls in C++-only machinery (<new>, type-trait templates) for its C++-
// aware paths. Those two needs can't both be satisfied by one #include in
// a C++ TU - wrapping it in extern "C" fixes the linkage for _cstr_init but
// breaks the C++-only parts, and leaving it unwrapped does the reverse.
// Compiled as plain C here, zt_internal.h behaves exactly as it does
// everywhere else in this codebase - no linkage question at all.

#include "zt_internal.h"

bool ztx_has_api_session(ziti_context ztx) {
    return ztx->session != NULL;
}
