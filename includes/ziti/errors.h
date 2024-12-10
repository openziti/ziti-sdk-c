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

/**
 * @file errors.h
 * @brief Defines the macros, functions, typedefs and constants pertaining to errors observed when using a Ziti Network
 */

#ifndef ZT_SDK_ERRORS_H

// @cond
#define ZT_SDK_ERRORS_H
// @endcond

#include "externs.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The expected outcome of a successful operation */
#define ZITI_OK                                                 (0)
/** The provided configuration was not found */
#define ZITI_CONFIG_NOT_FOUND                                   (-1)
/** The provided JWT was not found */
#define ZITI_JWT_NOT_FOUND                                      (-2)
/** The provided JWT is not accepted by the controller */
#define ZITI_JWT_INVALID                                        (-3)
/** The provided JWT has an invalid format */
#define ZITI_JWT_INVALID_FORMAT                                 (-4)
/** PKCS7/ASN.1 parsing failed */
#define ZITI_PKCS7_ASN1_PARSING_FAILED                          (-5)
/** unsupported JWT signing algorithm */
#define ZITI_JWT_SIGNING_ALG_UNSUPPORTED                        (-6)
/** JWT verification failed */
#define ZITI_JWT_VERIFICATION_FAILED                            (-7)
/** unsupported enrollment method */
#define ZITI_ENROLLMENT_METHOD_UNSUPPORTED                      (-8)
/** enrollment method requires client certificate */
#define ZITI_ENROLLMENT_CERTIFICATE_REQUIRED                    (-9)
/** Attempt to generate a private key failed */
#define ZITI_KEY_GENERATION_FAILED                              (-10)
/** Attempt to load TLS key failed */
#define ZITI_KEY_LOAD_FAILED                                    (-11)
/** Attempt to generate a CSR failed */
#define ZITI_CSR_GENERATION_FAILED                              (-12)
/** Some or all of the provided configuration is incorrect */
#define ZITI_INVALID_CONFIG                                     (-13)
/** the certificates presented are incorrect, out of date, or invalid */
#define ZITI_AUTHENTICATION_FAILED                              (-14)
/** Returned when the identity does not have the correct level of access needed.
* no policy exists granting the identity access for requestion operation */
#define ZITI_NOT_AUTHORIZED                                     (-15)
/** The SDK has attempted to communicate to the Ziti Controller but the controller
is offline or did not respond to the request*/
#define ZITI_CONTROLLER_UNAVAILABLE                             (-16)
/** The SDK cannot send data to the Ziti Network because an Edge Router was not available. Common causes are:
* the identity connecting is not associated with any Edge Routers
* the Edge Router in use is no longer responding */
#define ZITI_GATEWAY_UNAVAILABLE                                (-17)
/** The SDK cannot send data to the Ziti Network because the requested service was not available. Common causes are:
* the service does not exist
* the identity connecting is not associated with the given service */
#define ZITI_SERVICE_UNAVAILABLE                                (-18)
/** The connection has been closed gracefully */
#define ZITI_EOF                                                (-19)
/** A connect or write operation did not complete in the allocated timeout. #DEFAULT_TIMEOUT */
#define ZITI_TIMEOUT                                            (-20)
/** The connection has been closed abnormally. */
#define ZITI_CONNABORT                                          (-21)
/** SDK detected invalid state, most likely caused by improper use. */
#define ZITI_INVALID_STATE                                      (-22)
/** SDK detected invalid cryptographic state of Ziti connection */
#define ZITI_CRYPTO_FAIL                                        (-23)
/** connection was closed */
#define ZITI_CONN_CLOSED                                        (-24)
/** failed posture check */
#define ZITI_INVALID_POSTURE                                    (-25)
/** attempted to start MFA enrollment when it already has been started or completed */
#define ZITI_MFA_EXISTS                                         (-26)
/** attempted to use an MFA token that is invalid */
#define ZITI_MFA_INVALID_TOKEN                                  (-27)
/** attempted to verify or retrieve details of an MFA enrollment that has not been completed */
#define ZITI_MFA_NOT_ENROLLED                                   (-28)
/** not found, usually indicates stale reference or permission */
#define ZITI_NOT_FOUND                                          (-29)
/** operation attempted while ziti_context is not enabled */
#define ZITI_DISABLED                                           (-30)
/** returned when authentication is attempted but there is an existing api session waiting for auth queries to pass */
#define ZITI_PARTIALLY_AUTHENTICATED                            (-31)
/** returned during certificate authenticator extension if the authenticator cannot be extended because it is the wrong type (i.e. UPDB or 3rd party)*/
#define ZITI_INVALID_AUTHENTICATOR_TYPE                         (-32)
/** returned during certificate authentication extension when the current client cert does not match the authenticator*/
#define ZITI_INVALID_AUTHENTICATOR_CERT                         (-33)
/** returned when attempting to set the current certificate and key being used by a ztx when it could not be parsed/applied */
#define ZITI_INVALID_CERT_KEY_PAIR                              (-34)
/** returned when attempting to enroll the same key/cert with an external CA that has already been used */
#define ZITI_CERT_IN_USE                                        (-35)
/** returned when enrolling a key/cert with an external CA and no CA matches the cert */
#define ZITI_CERT_FAILED_VALIDATION                             (-36)
/** returned when the certificate doesn't have an externalId") \*/
#define ZITI_MISSING_CERT_CLAIM                                 (-37)
/** ziti could not allocate memory */
#define ZITI_ALLOC_FAILED                                       (-38)


// Put new error codes here and add error string in error.c

/** Inspired by the Android SDK: What a Terrible Failure. A condition that should never happen. */
#define ZITI_WTF (-111)

/**
* Returns a human-readable description for the provided code.
*/
ZITI_FUNC
extern const char *ziti_errorstr(int err);

#ifdef __cplusplus
}
#endif

#endif //ZT_SDK_ERRORS_H
