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
#include <stdlib.h>
#include <utils.h>
#include "zt_internal.h"

const char* APP_ID = NULL;
const char* APP_VERSION = NULL;

void ziti_set_app_info(const char *app_id, const char *app_version) {
    FREE(APP_ID);
    FREE(APP_VERSION);
    APP_ID = strdup(app_id);
    APP_VERSION = strdup(app_version);
}

static int load_config_file(const char *filename, ziti_config *cfg) {
    size_t config_len = 0;
    char *config = NULL;
    int rc = load_file(filename, 0, &config, &config_len);

    if (rc != 0) {
        ZITI_LOG(ERROR, "%s - %s", filename, uv_strerror(rc));
        return ZITI_CONFIG_NOT_FOUND;
    }

    if (parse_ziti_config(cfg, config, config_len) < 0) {
        free(config);
        return ZITI_INVALID_CONFIG;
    }
    cfg->cfg_source = strdup(filename);
    free(config);
    return ZITI_OK;
}

int ziti_load_config(ziti_config *cfg, const char* cfgstr) {
    if (!cfgstr) {
        return ZITI_INVALID_CONFIG;
    }

    memset(cfg, 0, sizeof(*cfg));
    int rc = parse_ziti_config(cfg, cfgstr, strlen(cfgstr));

    if (rc < 0) {
        ZITI_LOG(DEBUG, "trying to load config from file[%s]", cfgstr);
        rc = load_config_file(cfgstr, cfg);
    }

    if (rc < 0) {
        free_ziti_config(cfg);
    }

    return rc;
}
