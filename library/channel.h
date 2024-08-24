//
// 	Copyright NetFoundry Inc.
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
// Created by Eugene Kobyakov on 8/24/24.
//

#ifndef ZITI_SDK_CHANNEL_H
#define ZITI_SDK_CHANNEL_H

#include "zt_internal.h"

int zch_get_id(ziti_channel_t *ch);
const char* zch_get_name(ziti_channel_t *ch);
const char* zch_get_host(ziti_channel_t *ch);
bool zch_is_connected(ziti_channel_t *ch);

#endif //ZITI_SDK_CHANNEL_H
