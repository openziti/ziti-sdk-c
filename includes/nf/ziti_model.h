/*
Copyright (c) 2020 Netfoundry, Inc.

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


#ifndef ZITI_SDK_ZITI_MODEL_H
#define ZITI_SDK_ZITI_MODEL_H

#include "model_support.h"

#define ZITI_CTRL_VERSION(XX, ...) \
XX(version, string, none, version, __VA_ARGS__) \
XX(revision, string, none, revision, __VA_ARGS__) \
XX(build_date, string, none, buildDate, __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MODEL(ctrl_version, ZITI_CTRL_VERSION)

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_MODEL_H
