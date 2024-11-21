// Copyright (c) 2023.  NetFoundry Inc.
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

#include "ziti/errors.h"

#define ZITI_ERRORS(XX) \
    XX(OK, "OK") \
    XX(CONFIG_NOT_FOUND, "configuration not found") \
    XX(JWT_NOT_FOUND, "JWT not found") \
    XX(JWT_INVALID, "JWT not accepted by controller") \
    XX(JWT_INVALID_FORMAT, "JWT has invalid format") \
    XX(PKCS7_ASN1_PARSING_FAILED, "PKCS7/ASN.1 parsing failed") \
    XX(JWT_SIGNING_ALG_UNSUPPORTED, "unsupported JWT signing algorithm") \
    XX(JWT_VERIFICATION_FAILED, "JWT verification failed") \
    XX(ENROLLMENT_METHOD_UNSUPPORTED, "unsupported enrollment method") \
    XX(ENROLLMENT_CERTIFICATE_REQUIRED, "enrollment method requires certificate") \
    XX(KEY_GENERATION_FAILED, "error generating private key") \
    XX(KEY_LOAD_FAILED, "error loading TLS key") \
    XX(CSR_GENERATION_FAILED, "error generating a CSR") \
    XX(INVALID_CONFIG, "configuration is invalid")  \
    XX(AUTHENTICATION_FAILED, "failed to authenticate") \
    XX(NOT_AUTHORIZED, "not authorized") \
    XX(CONTROLLER_UNAVAILABLE, "ziti controller is not available") \
    XX(GATEWAY_UNAVAILABLE, "ziti edge router is not available") \
    XX(SERVICE_UNAVAILABLE, "service not available") \
    XX(EOF, "end of data") \
    XX(TIMEOUT, "operation did not complete in time") \
    XX(CONNABORT, "connection to edge router terminated") \
    XX(INVALID_STATE, "invalid state") \
    XX(CRYPTO_FAIL, "crypto failure") \
    XX(CONN_CLOSED, "connection is closed") \
    XX(INVALID_POSTURE, "failed posture check") \
    XX(MFA_EXISTS, "an MFA enrollment already exists") \
    XX(MFA_INVALID_TOKEN, "the token provided was invalid") \
    XX(MFA_NOT_ENROLLED, "the current identity has not completed MFA enrollment") \
    XX(NOT_FOUND, "entity no longer exists or is no longer accessible") \
    XX(DISABLED, "ziti context is disabled") \
    XX(PARTIALLY_AUTHENTICATED, "api session is partially authenticated, waiting for auth query resolution")               \
    XX(INVALID_AUTHENTICATOR_TYPE, "the authenticator could not be extended as it is the incorrect type")                  \
    XX(INVALID_AUTHENTICATOR_CERT, "the authenticator could not be extended as the current client certificate does not match") \
    XX(INVALID_CERT_KEY_PAIR, "the active certificate and key could not be set, invalid pair, or could not parse")         \
    XX(CERT_IN_USE,"the provided certificate already in use")       \
    XX(CERT_FAILED_VALIDATION, "the provided key/cert are invalid") \
    XX(WTF, "WTF: programming error")


#define ERR_NAME(e, s) case ZITI_##e: return s;

const char *ziti_errorstr(int err) {
    switch (err) {
        ZITI_ERRORS(ERR_NAME)

        default:
            return "unexpected error";
    }
}

#undef ERR_NAME