// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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

// The TOTP token a controller issues for a code (POST /current-api-session/totp-token), as far as the SDK looks at it.
#ifndef ZITI_SDK_TEST_TOTP_JWT_H
#define ZITI_SDK_TEST_TOTP_JWT_H

#include <cstring>
#include <string>

#include <sodium/utils.h>

namespace totp_test {
    // unpadded base64url, the encoding of the segments of a JWT (as the SDK decodes them)
    inline std::string b64url(const std::string &in) {
        const int variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
        std::string out(sodium_base64_ENCODED_LEN(in.size(), variant), '\0');
        sodium_bin2base64(out.data(), out.size(), reinterpret_cast<const unsigned char *>(in.data()), in.size(), variant);
        out.resize(strlen(out.c_str()));
        return out;
    }

    // signed (not really), no exp, scoped to an api session by z_asid; a null id leaves the claim out
    inline std::string totp_jwt(const char *api_session_id) {
        std::string payload = R"({"iss":"https://ctrl.example","sub":"identity-1","iat":1700000000,"z_t":"t")";
        if (api_session_id != nullptr) {
            payload += std::string(R"(,"z_asid":")") + api_session_id + "\"";
        }
        payload += "}";
        return b64url(R"({"alg":"none","typ":"JWT"})") + "." + b64url(payload) + ".c2ln";
    }
}

#endif // ZITI_SDK_TEST_TOTP_JWT_H
