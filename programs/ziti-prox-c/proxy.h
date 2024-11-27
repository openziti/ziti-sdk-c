// Copyright (c) 2024. NetFoundry Inc.
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

//
// Created by eugene on 11/25/24.
//

#ifndef PROXY_H
#define PROXY_H

#include <ziti/model_collections.h>

struct run_opts {
    int debug;
    const char *identity;
    model_list intercepts;
    model_list bindings;
    model_list udp_bindings;
    const char *proxy;
};

#if __cplusplus
extern "C" {
#endif

extern int run_proxy(struct run_opts*);

#if __cplusplus
    }
#endif

#endif //PROXY_H
