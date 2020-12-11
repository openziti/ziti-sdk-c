/*
Copyright (c) 2020 NetFoundry, Inc.

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


#ifndef ZITI_SDK_ZITI_EVENTS_H
#define ZITI_SDK_ZITI_EVENTS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZitiContextEvent = 1,
    ZitiEdgeRouterEvent = 1 << 1,
    ZitiServiceEvent = 1 << 2,
} ziti_event_type;

struct ziti_context_event {
    int ctrl_status;
    const char *err;
};

struct ziti_router_event {
    int TODO; // shut up windows
};

struct ziti_service_event {
    ziti_service_array removed;
    ziti_service_array changed;
    ziti_service_array added;
};

typedef struct ziti_event_s {
    ziti_event_type type;
    union {
        struct ziti_context_event ctx;
        struct ziti_router_event router;
        struct ziti_service_event service;
    } event;
} ziti_event_t;

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_EVENTS_H
