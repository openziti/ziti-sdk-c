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

#ifndef ZITI_SDK_DEADLINE_H
#define ZITI_SDK_DEADLINE_H

#include <tlsuv/queue.h>
#include <stdint.h>
#include "ziti/ziti_log.h"

typedef struct deadline_s deadline_t;
typedef LIST_HEAD(deadline_list, deadline_s) deadline_list_t;

struct deadline_s {
    LIST_ENTRY(deadline_s) _next;
    uint64_t expiration;
    void (*expire_cb)(void *ctx);
    const char *expire_cb_name;
    void *ctx;
};

static inline void clear_deadline(deadline_t *dl) {
    if (dl->expire_cb == NULL) return;

    ZITI_LOG(DEBUG, "expire_cb[%s]", dl->expire_cb_name);
    dl->expire_cb = NULL;
    dl->expire_cb_name = NULL;
    LIST_REMOVE(dl, _next);
}

#endif //ZITI_SDK_DEADLINE_H
