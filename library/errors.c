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
    XX(ZITI_OK, "OK") \
    XX(ZITI_CONFIG_NOT_FOUND, "configuration not found") \
    XX(ZITI_JWT_NOT_FOUND, "JWT not found") \
    XX(ZITI_JWT_INVALID, "JWT not accepted by controller") \
    XX(ZITI_JWT_INVALID_FORMAT, "JWT has invalid format") \
    XX(ZITI_PKCS7_ASN1_PARSING_FAILED, "PKCS7/ASN.1 parsing failed") \
    XX(ZITI_JWT_SIGNING_ALG_UNSUPPORTED, "unsupported JWT signing algorithm") \
    XX(ZITI_JWT_VERIFICATION_FAILED, "JWT verification failed") \
    XX(ZITI_ENROLLMENT_METHOD_UNSUPPORTED, "unsupported enrollment method") \
    XX(ZITI_ENROLLMENT_CERTIFICATE_REQUIRED, "enrollment method requires certificate") \
    XX(ZITI_KEY_GENERATION_FAILED, "error generating private key") \
    XX(ZITI_KEY_LOAD_FAILED, "error loading TLS key") \
    XX(ZITI_CSR_GENERATION_FAILED, "error generating a CSR") \
    XX(ZITI_INVALID_CONFIG, "configuration is invalid")  \
    XX(ZITI_AUTHENTICATION_FAILED, "failed to authenticate") \
    XX(ZITI_NOT_AUTHORIZED, "not authorized") \
    XX(ZITI_CONTROLLER_UNAVAILABLE, "ziti controller is not available") \
    XX(ZITI_GATEWAY_UNAVAILABLE, "ziti edge router is not available") \
    XX(ZITI_SERVICE_UNAVAILABLE, "service not available") \
    XX(ZITI_EOF, "end of data") \
    XX(ZITI_TIMEOUT, "operation did not complete in time") \
    XX(ZITI_CONNABORT, "connection to edge router terminated") \
    XX(ZITI_INVALID_STATE, "invalid state") \
    XX(ZITI_CRYPTO_FAIL, "crypto failure") \
    XX(ZITI_CONN_CLOSED, "connection is closed") \
    XX(ZITI_INVALID_POSTURE, "failed posture check") \
    XX(ZITI_MFA_EXISTS, "an MFA enrollment already exists") \
    XX(ZITI_MFA_INVALID_TOKEN, "the token provided was invalid") \
    XX(ZITI_MFA_NOT_ENROLLED, "the current identity has not completed MFA enrollment") \
    XX(ZITI_NOT_FOUND, "entity no longer exists or is no longer accessible") \
    XX(ZITI_DISABLED, "ziti context is disabled") \
    XX(ZITI_PARTIALLY_AUTHENTICATED, "api session is partially authenticated, waiting for auth query resolution")               \
    XX(ZITI_INVALID_AUTHENTICATOR_TYPE, "the authenticator could not be extended as it is the incorrect type")                  \
    XX(ZITI_INVALID_AUTHENTICATOR_CERT, "the authenticator could not be extended as the current client certificate does not match") \
    XX(ZITI_INVALID_CERT_KEY_PAIR, "the active certificate and key could not be set, invalid pair, or could not parse")         \
    XX(ZITI_CERT_IN_USE,"the provided certificate already in use")       \
    XX(ZITI_CERT_FAILED_VALIDATION, "the provided key/cert are invalid") \
    XX(ZITI_MISSING_CERT_CLAIM, "the certificate is expected to contain an externalId but none was not found") \
    XX(ZITI_ALLOC_FAILED, "memory allocation failed")    \
    XX(ZITI_EXTERNAL_LOGIN_REQUIRED, "identity required external login") \
    XX(ZITI_WTF, "WTF: programming error")


#define ERR_NAME(e, s) case e: return s;

const char *ziti_errorstr(int err) {
    switch (err) {
        ZITI_ERRORS(ERR_NAME)

        default:
            return "unexpected error";
    }
}

#undef ERR_NAME