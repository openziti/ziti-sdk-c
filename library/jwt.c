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
#include "ziti_model.h"



const char* ZITI_SDK_JWT_FILE = "ZITI_SDK_JWT_FILE";

static char* url64to64(const char* in, size_t ilen, size_t *olen) {
    size_t size = ((ilen - 1)/4 + 1) * 4;

    char *out = (char*)malloc(size);
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

int load_jwt_file(const char *filename, ziti_enrollment_jwt **zej) {
    ZITI_LOG(DEBUG, "filename is: %s", filename);
    struct stat stats;
    int s = stat(filename, &stats);
    if (s == -1) {
        ZITI_LOG(ERROR, "%s - %s", filename, strerror(errno));
        return ZITI_JWT_NOT_FOUND;
    }

    FILE* file = fopen(filename, "r");

    size_t jwt_file_len = (size_t) stats.st_size;
    char * jwt_file_content = malloc(jwt_file_len);
    size_t rc;
    if ((rc = fread(jwt_file_content, 1, jwt_file_len, file)) != jwt_file_len) {
        ZITI_LOG(WARN, "failed to read JWT file in full [%zd/%zd]: %s(%d)", rc, jwt_file_len, strerror(errno), errno);
    }
    fclose(file);

    ZITI_LOG(DEBUG, "jwt file content is: \n%s", jwt_file_content);


    const char *dot1 = strchr(jwt_file_content, '.');
    const char *dot2 = strchr(dot1 + 1, '.');
    const char *end = jwt_file_content + strlen(jwt_file_content);

    size_t header64len;
    char *header64 = url64to64(jwt_file_content, dot1 - jwt_file_content, &header64len);

    size_t head_len = (header64len / 4) * 3;

    char *head = (char*)malloc(head_len);
    char header[1024], body[1024];

    size_t body64len;
    char *body64 = url64to64(dot1 + 1, dot2 - dot1 - 1, &body64len);

    int rc2 = mjson_base64_dec(header64, header64len, head, head_len);

    char algo[32];
    rc2 = mjson_get_string(header, rc2, "$.alg", algo, sizeof(algo));

    rc2 = mjson_base64_dec(body64, body64len, body, sizeof(body));

    *zej = parse_ziti_enrollment_jwt(body, rc2);

    free(jwt_file_content);
    free(head);

    return ZITI_OK;
}

int load_jwt(const char *filename, ziti_enrollment_jwt **zej) {

    ZITI_LOG(DEBUG, "filename is: %s", filename);

    if (filename != NULL) {
        return load_jwt_file(filename, zej);
    }

    char *fn = getenv(ZITI_SDK_JWT_FILE);
    if (fn != NULL) {
        return load_jwt_file(fn, zej);
    }

    char def[1024];
    sprintf(def, "%s/.netfoundry/ziti/ziti.jwt", getenv("HOME"));
    return load_jwt_file(def, zej);
}
