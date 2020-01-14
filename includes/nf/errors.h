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

#ifndef ZT_SDK_ERRORS_H

// @cond
#define ZT_SDK_ERRORS_H
// @endcond

 /**
  * A macro defining the various errors conditions expected to be seen
  * when using the C SDK
  */
#define ZITI_ERRORS(XX) \
    /** The expected outcome of a successful operation */ \
    XX(OK, "OK") \
    /** The provided configuration was not found */ \
    XX(CONFIG_NOT_FOUND, "Configuration not found") \
    /** Some or all of the provided configuration is incorrect */ \
    XX(INVALID_CONFIG, "Configuration is invalid") \
    /** Returned when the identity does not have the correct level of access needed.
    Common causes are:
    * no policy exists granting the identity access
    * the certificates presented are incorrect, out of date, or invalid
    */ \
    XX(NOT_AUTHORIZED, "Not Authorized") \
    /** The SDK has attempted to communicate to the Ziti Controller but the controller
    is offline or did not respond to the request*/ \
    XX(CONTROLLER_UNAVAILABLE, "Ziti Controller is not available") \
    /** The SDK cannot send data to the Ziti Network because an Edge Router was not available. Common causes are:
    * the identity connecting is not associated with any Edge Routers
    * the Edge Router in use is no longer responding */ \
    XX(GATEWAY_UNAVAILABLE, "Ziti Gateway is not available") \
    /** The SDK cannot send data to the Ziti Network because the requested service was not available. Common causes are:
    * the service does not exist
    * the identity connecting is not associated with the given service
    */ \
    XX(SERVICE_UNAVALABLE, "Service not available") \
    /** The connection has been closed gracefully */ \
    XX(EOF, "Connection closed") \
    /** A connect or write operation did not complete in the alloted timeout. #DEFAULT_TIMEOUT */ \
    XX(TIMEOUT, "Operation did not complete in time") \
    /** The connection has been closed abnormally. */ \
    XX(CONNABORT, "Connection to edge router terminated") \
    /** Inspired by the Android SDK: What a Terrible Failure: A condition that should never happen. */ \
    XX(WTF, "WTF: programming error")


#ifdef __cplusplus
extern "C" {
#endif

/**
 * A helper macro to make declaring expected error conditions easier which is undef'ed immidately
 */
#define ERR_ID(e, _) extern const int ZITI_##e;
ZITI_ERRORS(ERR_ID)
#undef ERR_ID

/**
* Returns a human-readable description for the provided code.
*/
extern const char *ziti_errorstr(int err);

#ifdef __cplusplus
}
#endif

#endif //ZT_SDK_ERRORS_H
