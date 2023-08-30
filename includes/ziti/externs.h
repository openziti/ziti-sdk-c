// Copyright (c) 2020-2023.  NetFoundry Inc.
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


#ifndef ZITI_SDK_EXTERNS_H
#define ZITI_SDK_EXTERNS_H

#if defined(BUILDING_ZITI_SHARED) && defined(USING_ZITI_SHARED)
#error "Define either BUILDING_ZITI_SHARED or USING_ZITI_SHARED, not both."
#endif

#ifndef ZITI_FUNC

#ifdef _WIN32
# define ZITI_DEPRECATED(msg) __declspec(deprecated(msg))
# if defined(BUILDING_ZITI_SHARED)
#   define ZITI_FUNC __declspec(dllexport)
# elif defined(USING_ZITI_SHARED)
#   define ZITI_FUNC __declspec(dllimport)
# else
#   define ZITI_FUNC /* nothing */
# endif
#elif __GNUC__ >= 4
#  define ZITI_FUNC __attribute__((visibility("default")))
#  define ZITI_DEPRECATED(msg) __attribute((deprecated((msg))))
#else
# define ZITI_FUNC /* nothing */
#  define ZITI_DEPRECATED(msg)
#endif

#endif

#endif //ZITI_SDK_EXTERNS_H
