//
// Created by eugene on 2/28/19.
//
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