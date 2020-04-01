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

#include <string.h>
#include <zt_internal.h>
#include <mjson.h>
#include <utils.h>
#include "internal_model.h"
#include "ziti_enroll.h"


const char* ZITI_SDK_JWT_FILE = "ZITI_SDK_JWT_FILE";

static char* url64to64(const char* in, size_t ilen, size_t *olen) {
    size_t size = ((ilen - 1)/4 + 1) * 4;

    char *out = (char*)calloc(1, size + 1);
    size_t i;
    for(i = 0; i < ilen; i++) {
        switch (in[i]) {
            case '_': out[i] = '/'; break;
            case '-': out[i] = '+'; break;
            default: out[i] = in[i];
        }
    }

    while(i < size) {
        out[i++] = '=';
    }
    *olen = size;
    return out;
}

static const unsigned char pr2six[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static int base64url_decode_len(const char *bufcoded) {
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded;
}

static int base64url_decode(char *bufplain, const char *bufcoded) {
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
        *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes > 1)
        *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    if (nprbytes > 2)
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    if (nprbytes > 3)
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);

    size_t len = ((char*)bufout - bufplain);

    ZITI_LOG(DEBUG, "base64url_decode len is: %zu", len);

    return len;
}


int load_jwt_file(const char *filename, struct enroll_cfg_s *ecfg, ziti_enrollment_jwt_header **zejh, ziti_enrollment_jwt **zej) {
    ZITI_LOG(DEBUG, "filename is: %s", filename);

    struct stat stats;
    int s = stat(filename, &stats);
    if (s == -1) {
        ZITI_LOG(ERROR, "%s - %s", filename, strerror(errno));
        return ZITI_JWT_NOT_FOUND;
    }

    FILE* file = fopen(filename, "r");

    size_t jwt_file_len = (size_t) stats.st_size;
    ecfg->raw_jwt = calloc(1, jwt_file_len + 1);
    size_t rc;
    if ((rc = fread(ecfg->raw_jwt, 1, jwt_file_len, file)) != jwt_file_len) {
        ZITI_LOG(WARN, "failed to read JWT file in full [%zd/%zd]: %s(%d)", rc, jwt_file_len, strerror(errno), errno);
    }
    fclose(file);

    ZITI_LOG(DEBUG, "jwt file content is: \n%s", ecfg->raw_jwt);

    const char *dot1 = strchr(ecfg->raw_jwt, '.');
    if (NULL == dot1) {
        ZITI_LOG(ERROR, "%s - lacks a dot", filename);
        return ZITI_JWT_INVALID_FORMAT;
    }
    const char *dot2 = strchr(dot1 + 1, '.');
    if (NULL == dot2) {
        ZITI_LOG(ERROR, "%s - lacks a second dot", filename);
        return ZITI_JWT_INVALID_FORMAT;
    }
    ecfg->jwt_signing_input = (unsigned char*)calloc(1, strlen(ecfg->raw_jwt) + 1 );
    strncpy((char *)ecfg->jwt_signing_input, ecfg->raw_jwt, (dot2 - ecfg->raw_jwt) );
    ZITI_LOG(DEBUG, "ecfg->jwt_signing_input is: \n%s", ecfg->jwt_signing_input);

    size_t header64len;
    char *header64 = url64to64(ecfg->raw_jwt, dot1 - ecfg->raw_jwt, &header64len);

    size_t head_len = (header64len / 4) * 3;

    char *head = (char*)calloc(1, head_len + 1);
    char body[1024];

    size_t body64len;
    char *body64 = url64to64(dot1 + 1, dot2 - dot1 - 1, &body64len);

    ZITI_LOG(DEBUG, "sig is: \n%s", dot2 + 1);

    ecfg->jwt_sig = calloc(1, sizeof(char) * (base64url_decode_len(dot2 + 1)));
    ecfg->jwt_sig_len = base64url_decode(ecfg->jwt_sig, dot2 + 1);

    if (DEBUG <= ziti_debug_level) {
        hexDump("JWT sig", ecfg->jwt_sig, ecfg->jwt_sig_len);
    }

    int rc2 = mjson_base64_dec(header64, header64len, head, head_len);

    *zejh = calloc(1, sizeof(ziti_enrollment_jwt_header));
    if (parse_ziti_enrollment_jwt_header(*zejh, head, rc2) != 0) {
        free_ziti_enrollment_jwt_header(*zejh);
        FREE(*zejh);
        return ZITI_JWT_INVALID_FORMAT;
    }

    rc2 = mjson_base64_dec(body64, body64len, body, sizeof(body));

    *zej = calloc(1, sizeof(ziti_enrollment_jwt));
    if (parse_ziti_enrollment_jwt(*zej, body, rc2) != 0) {
        free_ziti_enrollment_jwt(*zej);
        FREE(*zej);
        return ZITI_JWT_INVALID_FORMAT;
    }

    free(head);

    return ZITI_OK;
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
