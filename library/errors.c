/*
Copyright 2019-2020 Netfoundry, Inc.

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

#include "nf/errors.h"

enum _zt_err {
#define _err_enum(e,_) _ziti_##e,
    ZITI_ERRORS(_err_enum)
};

#define ERR_ID(e,_) const int ZITI_##e = -_ziti_##e;
ZITI_ERRORS(ERR_ID)
#undef ERR_ID


#define ERR_NAME(e,s) case -_ziti_##e: return s;

const char* ziti_errorstr(int err) {
    switch (err) {
        ZITI_ERRORS(ERR_NAME)

        default:
            return "unexpected error";
    }

}
#undef ERR_NAME