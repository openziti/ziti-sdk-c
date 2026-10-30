// Copyright (c) 2022-2024. NetFoundry Inc.
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

/**
 * @file ziti.h
 * @brief Defines the macros, functions, typedefs and constants required to interface with a Ziti Network.
 *
 * This is the umbrella header of the Ziti C SDK API. It includes the per-concern headers below, which
 * can also be included on their own:
 * - handles.h: #ziti_context and #ziti_connection
 * - context.h: options, lifecycle, controller and identity info, service queries
 * - connection.h: dial, listen, accept, read and write, bridging
 * - posture.h: posture query callbacks and host state change
 * - mfa.h: MFA enrollment, verification and recovery codes
 * - ext_auth.h: external JWT signers and external authentication
 * - cert.h: client certificate and private key provisioning
 */

#ifndef ZITI_ZITI_H
#define ZITI_ZITI_H

#include <stdint.h>
#include <tlsuv/tlsuv.h>
#include <uv.h>
#include "errors.h"

#include "externs.h"
#include "ziti_model.h"
#include "enums.h"
#include "ziti_events.h"
#include "enroll.h"

#include "handles.h"
#include "context.h"
#include "connection.h"
#include "posture.h"
#include "mfa.h"
#include "ext_auth.h"
#include "cert.h"

#endif /* ZITI_ZITI_H */
