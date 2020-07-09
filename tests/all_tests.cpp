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

// tweaks for mips-openwrt build
// not sure if there is a better way
#if defined(mips) || defined(__mips)
#define nextafterl(x, y) nextafter(x,y)
#define CATCH_CONFIG_NO_CPP11_TO_STRING
#define CATCH_CONFIG_GLOBAL_NEXTAFTER
#endif

#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include "catch2/catch.hpp"
#include "../inc_internal/utils.h"

int init() {
    init_debug();
    return 0;
}

static int _init = init();
