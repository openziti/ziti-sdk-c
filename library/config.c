//
// Created by eugene on 2/27/19.
//

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <utils.h>
#include "zt_internal.h"

const char* ZITI_SDK_CONFIG = "ZITI_SDK_CONFIG";

int load_config_file(const char *filename, nf_config **cfg) {
    struct stat stats;
    int s = stat(filename, &stats);
    if (s == -1) {
        ZITI_LOG(ERROR, "%s - %s", filename, strerror(errno));
        return ZITI_CONFIG_NOT_FOUND;
    }

    FILE* file = fopen(filename, "r");

    size_t config_len = (size_t) stats.st_size;
    char * config = malloc(config_len);
    size_t rc;
    if ((rc = fread(config, 1, config_len, file)) != config_len) {
        ZITI_LOG(WARN, "failed to read config in full [%zd/%zd]: %s(%d)", rc, config_len, strerror(errno), errno);
    }
    fclose(file);

    *cfg = parse_nf_config(config, config_len);

    free(config);

    return ZITI_OK;
}

int load_config(const char *filename, nf_config **cfg) {
    if (filename != NULL) {
        return load_config_file(filename, cfg);
    }

    char *fn = getenv(ZITI_SDK_CONFIG);
    if (fn != NULL) {
        return load_config_file(fn, cfg);
    }

    char def[1024];
    sprintf(def, "%s/.netfoundry/ziti/id.json", getenv("HOME"));
    return load_config_file(def, cfg);
}
