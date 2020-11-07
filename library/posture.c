/*
Copyright (c) 2019-2020 NetFoundry, Inc.

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

#include "posture.h"

#include <utils.h>

#define NANOS(s) ((s) * 1e9)
#define MILLIS(s) ((s) * 1000)

static void ticker_cb(uv_timer_t *t);

static void ziti_handle_mac(ziti_context ztx, char *id, char **mac_addresses, int num_mac);

static void ziti_handle_domain(ziti_context ztx, char *id, char *domain);

static void ziti_handle_os(ziti_context ztx, char *id, char *os_type, char *os_version, char *os_build);

static void
ziti_handle_process(ziti_context ztx, char *id, char *path, bool is_running, char *sha_512_hash, char **signers,
                    int num_signers);

extern void posture_init(struct ziti_ctx *ztx, long interval_secs) {
    if (ztx->posture_checks == NULL) {
        NEWP(pc, struct posture_checks);
        pc->interval = (double) interval_secs;
        ztx->posture_checks = pc;
    }

    if (!uv_is_active((uv_handle_t *) &ztx->posture_checks->timer)) {
        uv_timer_init(ztx->loop, &ztx->posture_checks->timer);
        ztx->posture_checks->timer.data = ztx;
        uv_timer_start(&ztx->posture_checks->timer, ticker_cb, MILLIS(interval_secs), MILLIS(interval_secs));
        uv_unref((uv_handle_t *) &ztx->posture_checks->timer);
    }
}

extern void ziti_posture_checks_free(struct posture_checks *pcs) {
    FREE(pcs);
}

static void ticker_cb(uv_timer_t *t) {
    struct ziti_ctx *ztx = t->data;
    ziti_send_posture_data(ztx);
}

struct query_info {
    ziti_service *service;
    ziti_posture_query_set *query_set;
    ziti_posture_query *query;
};

void ziti_send_posture_data(struct ziti_ctx *ztx) {
    ZITI_LOG(DEBUG, "starting to send posture data");

    NEWP(domainInfo, struct query_info);
    NEWP(osInfo, struct query_info);
    NEWP(macInfo, struct query_info);

    struct query_info *procInfo = NULL;
    struct model_map processes = {NULL};

    const char *name;
    ziti_service *service;
    MODEL_MAP_FOREACH(name, service, &ztx->services) {
        if(service->posture_query_set == NULL) {
            continue;
        }

        int setIdx = 0;
        ziti_posture_query_set *set = NULL;
        while (service->posture_query_set[setIdx] != NULL) {
            set = service->posture_query_set[setIdx];
            int queryIdx = 0;
            while (set->posture_queries[queryIdx] != NULL) {
                ziti_posture_query *query = set->posture_queries[queryIdx];
                if (strcmp(query->query_type, PC_MAC_TYPE) == 0) {
                    macInfo->query_set = set;
                    macInfo->query = query;
                    macInfo->service = service;
                } else if (strcmp(query->query_type, PC_DOMAIN_TYPE) == 0) {
                    domainInfo->query_set = set;
                    domainInfo->query = query;
                    domainInfo->service = service;
                } else if (strcmp(query->query_type, PC_OS_TYPE) == 0) {
                    osInfo->query_set = set;
                    osInfo->query = query;
                    osInfo->service = service;
                } else if (strcmp(query->query_type, PC_PROCESS_TYPE) == 0) {

                    void *curVal = model_map_get(&processes, query->process->path);
                    if (curVal == NULL) {
                        NEWP(newProcInfo, struct query_info);
                        newProcInfo->query_set = set;
                        newProcInfo->query = query;
                        newProcInfo->service = service;
                        model_map_set(&processes, query->process->path, newProcInfo);
                        if (procInfo == NULL) {
                            procInfo = newProcInfo;
                        }
                    }
                }
                queryIdx++;
            }
            setIdx++;
        }
    }

    if (domainInfo->query != NULL) {
        if (ztx->opts->pq_domain_cb != NULL) {
            ztx->opts->pq_domain_cb(ztx, domainInfo->query->id, ziti_handle_domain);
        } else {
            ZITI_LOG(DEBUG, "%s cb not set requested for: service %s, policy: %s, check: %s", PC_DOMAIN_TYPE,
                     domainInfo->service->name, domainInfo->query_set->policy_id, domainInfo->query->id);
        }
    }

    if (macInfo->query != NULL) {
        if (ztx->opts->pq_mac_cb != NULL) {
            ztx->opts->pq_mac_cb(ztx, macInfo->query->id, ziti_handle_mac);
        } else {
            ZITI_LOG(DEBUG, "%s cb not set requested for: service %s, policy: %s, check: %s", PC_MAC_TYPE,
                     macInfo->service->name, macInfo->query_set->policy_id, macInfo->query->id);
        }
    }

    if (osInfo->query != NULL) {
        if (ztx->opts->pq_os_cb != NULL) {
            ztx->opts->pq_os_cb(ztx, osInfo->query->id, ziti_handle_os);
        } else {
            ZITI_LOG(DEBUG, "%s cb not set requested for: service %s, policy: %s, check: %s", PC_OS_TYPE,
                     osInfo->service->name, osInfo->query_set->policy_id, osInfo->query->id);
        }
    }

    if (procInfo != NULL) {
        const char *path;
        struct query_info *info;

        if (ztx->opts->pq_process_cb != NULL) {
            MODEL_MAP_FOREACH(path, info, &processes) {
                ztx->opts->pq_process_cb(ztx, info->query->id, path, ziti_handle_process);
            }
        } else {
            ZITI_LOG(DEBUG, "%s cb not set requested for: service %s, policy: %s, check: %s", PC_PROCESS_TYPE,
                     osInfo->service->name, osInfo->query_set->policy_id, osInfo->query->id);
        }
    }

    model_map_clear(&processes, NULL);

    ZITI_LOG(DEBUG, "done sending posture data, free");
    free(domainInfo);
    free(osInfo);
    free(macInfo);
    //no free(procInfo), free'ed in map
    ZITI_LOG(DEBUG, "done sending posture data");
}

static void ziti_handle_mac(ziti_context ztx, char *id, char **mac_addresses, int num_mac) {
    ziti_ctrl_pr_post_mac(&ztx->controller, id, mac_addresses, num_mac, NULL, ztx);
}

static void ziti_handle_domain(ziti_context ztx, char *id, char *domain) {
    ziti_ctrl_pr_post_domain(&ztx->controller, id, domain, NULL, ztx);
}

static void ziti_handle_os(ziti_context ztx, char *id, char *os_type, char *os_version, char *os_build) {
    ziti_ctrl_pr_post_os(&ztx->controller, id, os_type, os_version, os_build, NULL, ztx);
}


static void
ziti_handle_process(ziti_context ztx, char *id, char *path, bool is_running, char *sha_512_hash, char **signers,
                    int num_signers) {
    ziti_ctrl_pr_post_process(&ztx->controller, id, is_running, sha_512_hash, signers, num_signers,
                              NULL,
                              ztx);
}


