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

#include <string.h>
#include <zt_internal.h>

#define MAX_JWT_LEN 8196

const char* ZITI_SDK_JWT_FILE = "ZITI_SDK_JWT_FILE";

int parse_jwt_content(struct enroll_cfg_s *ecfg, ziti_enrollment_jwt_header **zejh, ziti_enrollment_jwt **zej) {

    const char *dot1 = strchr(ecfg->raw_jwt, '.');
    if (NULL == dot1) {
        ZITI_LOG(ERROR, "jwt input lacks a dot");
        return ZITI_JWT_INVALID_FORMAT;
    }
    const char *dot2 = strchr(dot1 + 1, '.');
    if (NULL == dot2) {
        ZITI_LOG(ERROR, "jwt input lacks a second dot");
        return ZITI_JWT_INVALID_FORMAT;
    }
    ecfg->jwt_signing_input = (unsigned char *) calloc(1, strlen(ecfg->raw_jwt) + 1);
    strncpy((char *) ecfg->jwt_signing_input, ecfg->raw_jwt, (dot2 - ecfg->raw_jwt));
    ZITI_LOG(DEBUG, "ecfg->jwt_signing_input is: \n%s", ecfg->jwt_signing_input);
    tlsuv_base64url_decode(dot2 + 1, &ecfg->jwt_sig, &ecfg->jwt_sig_len);

    size_t header_len;
    char *header;
    tlsuv_base64url_decode(ecfg->raw_jwt, &header, &header_len);

    *zejh = calloc(1, sizeof(ziti_enrollment_jwt_header));
    if (parse_ziti_enrollment_jwt_header(*zejh, header, header_len) < 0) {
        free_ziti_enrollment_jwt_header(*zejh);
        FREE(*zejh);
        return ZITI_JWT_INVALID_FORMAT;
    }
    free(header);

    size_t blen;
    char *body;
    tlsuv_base64url_decode(dot1 + 1, &body, &blen);

    *zej = calloc(1, sizeof(ziti_enrollment_jwt));
    if (parse_ziti_enrollment_jwt(*zej, body, blen) < 0) {
        free_ziti_enrollment_jwt(*zej);
        FREE(*zej);
        return ZITI_JWT_INVALID_FORMAT;
    }
    free(body);
    return ZITI_OK;
}

int load_jwt_file(const char *filename, struct enroll_cfg_s *ecfg, ziti_enrollment_jwt_header **zejh, ziti_enrollment_jwt **zej) {

    FILE *jwt_input;
    if (strcmp(filename, "-") == 0) {
        ZITI_LOG(DEBUG, "reading JWT from standard input");
        jwt_input = stdin;
    } else {
        ZITI_LOG(DEBUG, "reading JWT from file: %s", filename);

        struct stat stats;
        int s = stat(filename, &stats);
        if (s == -1) {
            ZITI_LOG(ERROR, "%s - %s", filename, strerror(errno));
            return ZITI_JWT_NOT_FOUND;
        }

        jwt_input = fopen(filename, "r");
        if (jwt_input == NULL) {
            ZITI_LOG(ERROR, "failed to open file(%s): %d(%s)", filename, errno, strerror(errno));
        }
    }


    size_t jwt_file_len = (size_t) MAX_JWT_LEN;
    ecfg->raw_jwt = calloc(1, jwt_file_len + 1);
    size_t rc = fread(ecfg->raw_jwt, 1, jwt_file_len, jwt_input);
    if (rc <= 0) {
        ZITI_LOG(WARN, "failed to read JWT file: %d(%s)", errno, strerror(errno));
        fclose(jwt_input);
        return ZITI_JWT_INVALID;
    }
    jwt_file_len = rc;
    fclose(jwt_input);

    ZITI_LOG(DEBUG, "jwt file content is: \n%.*s", (int) jwt_file_len, ecfg->raw_jwt);

    return parse_jwt_content(ecfg, zejh, zej);
}

int load_jwt(const char *filename, struct enroll_cfg_s *ecfg, ziti_enrollment_jwt_header **zejh, ziti_enrollment_jwt **zej) {

    ZITI_LOG(DEBUG, "filename is: %s", filename);

    if (filename != NULL) {
        return load_jwt_file(filename, ecfg, zejh, zej);
    }

    char *fn = getenv(ZITI_SDK_JWT_FILE);
    if (fn != NULL) {
        return load_jwt_file(fn, ecfg, zejh, zej);
    }

    char def[1024];
    sprintf(def, "%s/.netfoundry/ziti/ziti.jwt", getenv("HOME"));
    return load_jwt_file(def, ecfg, zejh, zej);
}

int load_jwt_content(struct enroll_cfg_s *ecfg, ziti_enrollment_jwt_header **zejh, ziti_enrollment_jwt **zej) {

    ZITI_LOG(VERBOSE, "jwt file content is: \n%.*s", (int) strlen(ecfg->raw_jwt), ecfg->raw_jwt);

    return parse_jwt_content(ecfg, zejh, zej);
}
