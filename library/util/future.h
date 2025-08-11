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

#ifndef ZITI_SDK_FUTURE_H
#define ZITI_SDK_FUTURE_H

typedef struct future_s future_t;

future_t *new_future(void);

void destroy_future(future_t *f);

int await_future_timed(future_t *f, void **result, uint64_t timeout);
int await_future(future_t *f, void **result);

int complete_future(future_t *f, void *result, int code);

int fail_future(future_t *f, int err);

#endif //ZITI_SDK_FUTURE_H
