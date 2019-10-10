//
// Created by eugene on 2/28/19.
//

#ifndef ZT_SDK_ERRORS_H
#define ZT_SDK_ERRORS_H

#define ZITI_ERRORS(XX) \
    XX(OK, "OK") \
    XX(CONFIG_NOT_FOUND, "Configuration not found") \
    XX(NOT_AUTHORIZED, "Not Authorized") \
    XX(CONTROLLER_UNAVAILABLE, "Ziti Controller is not available") \
    XX(GATEWAY_UNAVAILABLE, "Ziti Gateway is not available") \
    XX(SERVICE_UNAVALABLE, "Service not available") \
    XX(EOF, "Connection closed") \
    XX(TIMEOUT, "Operation did not complete in time") \
    XX(CONNABORT, "Connection to gateway terminated") \
    XX(KEY_SPEC_UNSUPPORTED, "unsupported key specification") \
    XX(KEY_INVALID, "invalid key") \
    XX(WTF, "WTF: programming error")


#ifdef __cplusplus
extern "C" {
#endif

#define ERR_ID(e, _) extern const int ZITI_##e;
ZITI_ERRORS(ERR_ID)
#undef ERR_ID

extern const char *ziti_errorstr(int err);

#ifdef __cplusplus
}
#endif

#endif //ZT_SDK_ERRORS_H
