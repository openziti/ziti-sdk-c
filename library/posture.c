// Copyright (c) 2019-2022.  NetFoundry Inc.
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

#include "edge_protocol.h"
#include "posture.h"
#include <utils.h>

#if _WIN32
#include <winnt.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <lmcons.h>
#include <lmapibuf.h>
#include <lmjoin.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#include <VersionHelpers.h>
#include <windows.h>


#elif __APPLE__ && __MACH__
   #include <TargetConditionals.h>
   #if TARGET_OS_IPHONE == 0 && TARGET_OS_SIMULATOR == 0
      #include <libproc.h>
   #endif
#endif

#define NANOS(s) ((s) * 1e9)
#define MILLIS(s) ((s) * 1000)

const int NO_TIMEOUTS = -1;

const bool IS_ERRORED = true;
const bool IS_NOT_ERRORED = false;

#define PC_DOMAIN_TYPE ziti_posture_query_types.name(ziti_posture_query_types.PC_Domain)
#define PC_OS_TYPE ziti_posture_query_types.name(ziti_posture_query_types.PC_OS)
#define PC_MAC_TYPE ziti_posture_query_types.name(ziti_posture_query_types.PC_MAC)

#define s_strdup(s) ((s) ? strdup(s) : NULL)

struct query_info {
    ziti_service *service;
    ziti_posture_query_set *query_set;
    ziti_posture_query *query;
};

struct pr_info_s {
    char *id;
    ziti_pr_base *obj;
    bool should_send;
    bool pending;
    bool obsolete;
};

typedef struct pr_info_s pr_info;

struct pr_cb_ctx_s {
    ziti_context ztx;
    pr_info *info;
};

struct process_work {
    uv_work_t w;
    bool canceled;
    char *id;
    char *path;
    ziti_context ztx;
    ziti_pr_process_cb cb;

    bool is_running;
    char *sha512;
    char **signers;
    int num_signers;
};

typedef struct pr_cb_ctx_s pr_cb_ctx;

static void free_ziti_pr(ziti_pr_base *pr);

static void ziti_pr_ticker_cb(void *data);

static void ziti_pr_handle_mac(ziti_context ztx, const char *id, char **mac_addresses, int num_mac);

static void ziti_pr_handle_domain(ziti_context ztx, const char *id, const char *domain);

static void ziti_pr_handle_os(ziti_context ztx, const char *id, const char *os_type, const char *os_version, const char *os_build);

static void ziti_pr_handle_process(ziti_context ztx, const char *id, const char *path,
                                   bool is_running, const char *sha_512_hash, char **signers, int num_signers);

static void ziti_pr_send(ziti_context ztx);

static void ziti_pr_send_bulk(ziti_context ztx);

static bool ziti_pr_is_info_errored(ziti_context ztx, const char *id);

static void default_pq_os(ziti_context ztx, const char *id, ziti_pr_os_cb response_cb);

static void default_pq_mac(ziti_context ztx, const char *id, ziti_pr_mac_cb response_cb);

static void default_pq_domain(ziti_context ztx, const char *id, ziti_pr_domain_cb cb);

static void default_pq_process(ziti_context ztx, const char *id, const char *path, ziti_pr_process_cb cb);

static char **get_signers(const char *path, int *signers_count);

static int hash_sha512(ziti_context ztx, uv_loop_t *loop, const char *path, unsigned char **out_buf, size_t *out_len);

static bool check_running(uv_loop_t *loop, const char *path);

static void send_posture_legacy(ziti_context ztx, model_list *send_prs);

static void send_posture_ha(ziti_context ztx, model_list *send_prs);

static void ziti_pr_free_pr_info(pr_info *info) {
    FREE(info->id);
    free_ziti_pr(info->obj);
    FREE(info);
}

void ziti_posture_init(ziti_context ztx, long interval_secs) {
    if (ztx->posture_checks == NULL) {
        NEWP(pc, struct posture_checks);

        pc->previous_api_session_id = NULL;
        pc->controller_instance_id = NULL;
        pc->must_send_every_time = true;
        pc->must_send = false;
        pc->send_period = interval_secs * 1000;

        ztx->posture_checks = pc;
    }

    ztx_set_deadline(ztx, 1, &ztx->posture_checks->deadline, ziti_pr_ticker_cb, ztx);
}

void ziti_posture_checks_free(struct posture_checks *pcs) {
    if (pcs != NULL) {
        clear_deadline(&pcs->deadline);
        model_map_clear(&pcs->responses, (_free_f) ziti_pr_free_pr_info);
        model_map_clear(&pcs->error_states, NULL);
        model_map_iter it = model_map_iterator(&pcs->active_work);
        while (it) {
            struct process_work *pwk = model_map_it_value(it);
            pwk->canceled = true;
            it = model_map_it_remove(it);
        }
        FREE(pcs->previous_api_session_id);
        FREE(pcs->controller_instance_id);
        FREE(pcs);
    }
}

static void ziti_pr_ticker_cb(void *data) {
    ziti_context ztx = (ziti_context) data;
    ziti_send_posture_data(ztx);
    ztx_set_deadline(ztx, ztx->posture_checks->send_period, &ztx->posture_checks->deadline, ziti_pr_ticker_cb, ztx);
}

static pr_info *get_resp_info(ziti_context ztx, const char *id) {
    pr_info *resp = model_map_get(&ztx->posture_checks->responses, id);
    if (resp == NULL) {
        resp = calloc(1, sizeof(pr_info));
        resp->id = strdup(id);
        model_map_set(&ztx->posture_checks->responses, id, resp);
    }
    return resp;
}

void ziti_send_posture_data(ziti_context ztx) {
    struct posture_checks *checks = ztx->posture_checks;
    if (!checks) {
        ZTX_LOG(DEBUG, "endpoint is disabled");
        return;
    }

    if(ztx->auth_state != ZitiAuthStateFullyAuthenticated) {
        ZTX_LOG(DEBUG, "api_session is partially authenticated, can't submit posture responses");
        return;
    }

    ZTX_LOG(VERBOSE, "starting to send posture data");
    bool new_session_id = checks->previous_api_session_id == NULL ||
                          strcmp(checks->previous_api_session_id, ztx->session_token) != 0;

    ziti_controller *ctrl = ztx_get_controller(ztx);
    bool new_controller_instance =
            (checks->controller_instance_id == NULL && ctrl->instance_id != NULL) ||
            strcmp(checks->controller_instance_id, ctrl->instance_id) != 0;

    if(new_controller_instance){
        ZTX_LOG(INFO, "first run or potential controller restart detected");
    }

    if (new_session_id || checks->must_send_every_time || new_controller_instance) {
        ZTX_LOG(DEBUG, "posture checks must_send set to TRUE, new_session_id[%s], must_send_every_time[%s], new_controller_instance[%s]",
                new_session_id ? "TRUE" : "FALSE",
                checks->must_send_every_time ? "TRUE" : "FALSE",
                new_controller_instance ? "TRUE" : "FALSE");

        checks->must_send = true;
        FREE(checks->previous_api_session_id);
        FREE(checks->controller_instance_id);
        checks->previous_api_session_id = strdup(ztx->session_token);
        checks->controller_instance_id = strdup(ctrl->instance_id);
    } else {
        ZTX_LOG(DEBUG, "posture checks must_send set to FALSE, new_session_id[%s], must_send_every_time[%s], new_controller_instance[%s]",
                new_session_id ? "TRUE" : "FALSE",
                checks->must_send_every_time ? "TRUE" : "FALSE",
                new_controller_instance ? "TRUE" : "FALSE");

        checks->must_send = false;
    }

    struct query_info
            domainInfo = {},
            osInfo = {},
            macInfo = {};

    struct model_map processes = {NULL};

    __attribute__((unused)) const char *name;
    ziti_service *service;

    ZTX_LOG(VERBOSE, "checking posture queries on %zd service(s)", model_map_size(&ztx->services));

    //loop over the services and determine the query types that need responses
    //for process queries, save them by process path
    MODEL_MAP_FOREACH(name, service, &ztx->services) {
        if (model_map_size(&service->posture_query_map) == 0) {
            continue;
        }

        const char *policy_id;
        ziti_posture_query_set *set;
        MODEL_MAP_FOREACH(policy_id, set, &service->posture_query_map) {
            int queryIdx = 0;
            while (set->posture_queries[queryIdx] != NULL) {
                ziti_posture_query *query = set->posture_queries[queryIdx];
                switch (query->query_type) {
                    case ziti_posture_query_type_PC_MAC:
                        macInfo.query_set = set;
                        macInfo.query = query;
                        macInfo.service = service;
                        break;
                    case ziti_posture_query_type_PC_Domain:
                        domainInfo.query_set = set;
                        domainInfo.query = query;
                        domainInfo.service = service;
                        break;
                    case ziti_posture_query_type_PC_OS:
                        osInfo.query_set = set;
                        osInfo.query = query;
                        osInfo.service = service;
                        break;
                    case ziti_posture_query_type_PC_Process: {
                        void *curVal = model_map_get(&processes, query->process->path);
                        if (curVal == NULL) {
                            NEWP(newProcInfo, struct query_info);
                            newProcInfo->query_set = set;
                            newProcInfo->query = query;
                            newProcInfo->service = service;
                            model_map_set(&processes, query->process->path, newProcInfo);
                        }
                        break;
                    }
                    case ziti_posture_query_type_PC_Process_Multi: {
                        int processIdx = 0;
                        while (query->processes[processIdx] != NULL) {
                            ziti_process *process = query->processes[processIdx];

                            void *curVal = model_map_get(&processes, process->path);
                            if (curVal == NULL) {
                                NEWP(newProcInfo, struct query_info);
                                newProcInfo->query_set = set;
                                newProcInfo->query = query;
                                newProcInfo->service = service;

                                model_map_set(&processes, process->path, newProcInfo);
                            }
                            processIdx++;
                        }
                        break;
                    }
                    case ziti_posture_query_type_PC_MFA:
                    case ziti_posture_query_type_PC_Endpoint_State:
                        break;
                    case ziti_posture_query_type_Unknown:
                        ZTX_LOG(WARN, "unknown posture query type for id[%s]", query->id);
                        break;
                }
                queryIdx++;
            }
        }
    }

    // mark responses obsolete in case they were removed
    pr_info *resp;
    MODEL_MAP_FOREACH(name, resp, &checks->responses) {
        if (!resp->pending && !resp->should_send) {
            resp->obsolete = true;
        }
    }

    if (domainInfo.query != NULL) {
        if (domainInfo.query->timeout == NO_TIMEOUTS) {
            checks->must_send_every_time = false;
        }

        resp = get_resp_info(ztx, PC_DOMAIN_TYPE);
        resp->obsolete = false;
        if (!resp->pending) {
            resp->pending = true;
            if (ztx->opts.pq_domain_cb != NULL) {
                ztx->opts.pq_domain_cb(ztx, domainInfo.query->id, ziti_pr_handle_domain);
            } else {
                ZTX_LOG(VERBOSE, "using default %s cb for: service %s, policy: %s, check: %s", PC_DOMAIN_TYPE,
                         domainInfo.service->name, domainInfo.query_set->policy_id, domainInfo.query->id);
                default_pq_domain(ztx, domainInfo.query->id, ziti_pr_handle_domain);
            }
        }
    }

    if (macInfo.query != NULL) {
        if (macInfo.query->timeout == NO_TIMEOUTS) {
            checks->must_send_every_time = false;
        }

        resp = get_resp_info(ztx, PC_MAC_TYPE);
        resp->obsolete = false;
        if (!resp->pending) {
            resp->pending = true;
            if (ztx->opts.pq_mac_cb != NULL) {
                ztx->opts.pq_mac_cb(ztx, macInfo.query->id, ziti_pr_handle_mac);
            } else {
                ZTX_LOG(VERBOSE, "using default %s cb for: service %s, policy: %s, check: %s", PC_MAC_TYPE,
                         macInfo.service->name, macInfo.query_set->policy_id, macInfo.query->id);
                default_pq_mac(ztx, macInfo.query->id, ziti_pr_handle_mac);
            }
        }
    }

    if (osInfo.query != NULL) {
        if (osInfo.query->timeout == NO_TIMEOUTS) {
            checks->must_send_every_time = false;
        }
        resp = get_resp_info(ztx, PC_OS_TYPE);
        resp->obsolete = false;
        if (!resp->pending) {
            resp->pending = true;
            if (ztx->opts.pq_os_cb != NULL) {
                ztx->opts.pq_os_cb(ztx, osInfo.query->id, ziti_pr_handle_os);
            } else {
                ZTX_LOG(VERBOSE, "using default %s cb for: service %s, policy: %s, check: %s", PC_OS_TYPE,
                         osInfo.service->name, osInfo.query_set->policy_id, osInfo.query->id);
                default_pq_os(ztx, osInfo.query->id, ziti_pr_handle_os);
            }
        }
    }

    if (model_map_size(&processes) > 0) {
        const char *path;
        struct query_info *info;

        ziti_pq_process_cb proc_cb = ztx->opts.pq_process_cb;
        if (proc_cb == NULL) {
            proc_cb = default_pq_process;
            ZTX_LOG(VERBOSE, "using default cb for process queries");
        }
        MODEL_MAP_FOREACH(path, info, &processes) {
            if (info->query->timeout == NO_TIMEOUTS) {
                checks->must_send_every_time = false;
            }
            resp = get_resp_info(ztx, path);
            resp->obsolete = false;
            if (!resp->pending) {
                resp->pending = true;
                proc_cb(ztx, info->query->id, path, ziti_pr_handle_process);
            }
        }
    }

    model_map_iter it = model_map_iterator(&checks->responses);
    while (it) {
        resp = model_map_it_value(it);
        if (resp->obsolete) {
            ZTX_LOG(DEBUG, "removing obsolete posture resp[%s],  should_send = %s, pending = %s", 
                    resp->id, resp->should_send ? "true" : "false", resp->pending ? "true" : "false");
            it = model_map_it_remove(it);
            ziti_pr_free_pr_info(resp);
        } else {
            it = model_map_it_next(it);
        }
    }

    model_map_clear(&processes, free);

    ziti_pr_send(ztx);
}

static const char *ziti_pr_key(ziti_pr_base *pr) {
    if (pr->typeId == ziti_posture_query_type_PC_Process) {
        return ((ziti_pr_process_req*)pr)->path;
    }

    return ziti_posture_query_types.name(pr->typeId);
}

static const type_meta * get_pr_req_meta(ziti_posture_query_type type_id) {
    const type_meta *meta = NULL;
    switch (type_id) {
        case ziti_posture_query_type_PC_Domain: meta = get_ziti_pr_domain_req_meta(); break;
        case ziti_posture_query_type_PC_OS: meta = get_ziti_pr_os_req_meta(); break;
        case ziti_posture_query_type_PC_Process: meta = get_ziti_pr_process_req_meta(); break;
        case ziti_posture_query_type_PC_MAC: meta = get_ziti_pr_mac_req_meta(); break;
        case ziti_posture_query_type_PC_Endpoint_State: meta = get_ziti_pr_endpoint_state_req_meta(); break;
        default:
            ZITI_LOG(WARN, "can't get meta for posture resp type[%s]", ziti_posture_query_types.name(type_id));
    }
    return meta;
}

static bool ziti_pr_changed(const ziti_pr_base *lhs, const ziti_pr_base *rhs) {
    if (lhs == NULL && rhs == NULL) return false;
    if (lhs == NULL) return true;
    if (rhs == NULL) return true;
    if (lhs->typeId != rhs->typeId) return true;

    const type_meta *meta = get_pr_req_meta(lhs->typeId);
    if (meta) {
        return model_cmp(lhs, rhs, meta) != 0;
    }
    
    return true;
}
static void free_ziti_pr(ziti_pr_base *pr) {
    if (pr == NULL) return;

    switch (pr->typeId) {
        case ziti_posture_query_type_Unknown:
        case ziti_posture_query_type_PC_Process_Multi:
        case ziti_posture_query_type_PC_MFA:
            ZITI_LOG(WARN, "should not be here -- possible memory leak");
            free_ziti_pr_base_ptr(pr);
            break;
        case ziti_posture_query_type_PC_Domain:
            free_ziti_pr_domain_req_ptr((ziti_pr_domain_req *) pr);
            break;
        case ziti_posture_query_type_PC_OS:
            free_ziti_pr_os_req_ptr((ziti_pr_os_req *) pr);
            break;
        case ziti_posture_query_type_PC_Process:
            free_ziti_pr_process_req_ptr((ziti_pr_process_req *) pr);
            break;
        case ziti_posture_query_type_PC_MAC:
            free_ziti_pr_mac_req_ptr((ziti_pr_mac_req *) pr);
            break;
        case ziti_posture_query_type_PC_Endpoint_State:
            free_ziti_pr_endpoint_state_req_ptr((ziti_pr_endpoint_state_req *) pr);
            break;
    }
}

static void ziti_collect_pr(ziti_context ztx, void *req) {
    ziti_pr_base *pr = req;
    const char *pr_key = ziti_pr_key(pr);
    if (ztx->posture_checks == NULL) {
        ZTX_LOG(WARN, "ztx disabled, posture check obsolete id[%s]", pr_key);
        free_ziti_pr(req);
        return;
    }

    pr_info *current_info = model_map_get(&ztx->posture_checks->responses, pr_key);

    if (current_info != NULL) {
        current_info->pending = false;

        bool changed = ziti_pr_changed(current_info->obj, pr);
        if (changed) {
            free_ziti_pr(current_info->obj);
            current_info->obj = pr;
        } else {
            free_ziti_pr(pr);
        }

        current_info->should_send = ztx->posture_checks->must_send_every_time || ziti_pr_is_info_errored(ztx, current_info->id) || changed;
    } else {
        ZTX_LOG(WARN, "response info not found, posture check obsolete? id[%s]", pr_key);
        free_ziti_pr(pr);
    }
}

static void handle_pr_resp_timer_events(ziti_context ztx, ziti_pr_response *pr_resp){
    ZTX_LOG(DEBUG, "handle_pr_resp_timer_events: starting");

    if(pr_resp != NULL && pr_resp->services != NULL) {
        ziti_service_timer **service_timer;
        for(service_timer = pr_resp->services; *service_timer != NULL; service_timer++){
            NEWP(val, bool);
            *val = true;
            ZTX_LOG(DEBUG, "handle_pr_resp_timer_events: forcing service name[%s] id[%s] with timeout[%d] timeoutRemaining[%d]",
                    (*service_timer)->name, (*service_timer)->id, (int)*(*service_timer)->timeout, (int)*(*service_timer)->timeoutRemaining);
            ziti_force_service_update(ztx, (*service_timer)->id);
        }

    } else {
        ZTX_LOG(DEBUG, "handle_pr_resp_timer_events: pr_resp or pr_resp.services was null");
    }

    ZTX_LOG(DEBUG, "handle_pr_resp_timer_events: done");
}

static void ziti_pr_post_bulk_cb(ziti_pr_response *pr_resp, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    ZTX_LOG(DEBUG, "ziti_pr_post_bulk_cb: starting");

    // if ztx is disabled this request is cancelled and posture_checks is cleared
    if (ztx->posture_checks) {
        if (err != NULL) {
            ZTX_LOG(ERROR, "error during bulk posture response submission (%d) %s", (int)err->http_code, err->message);
            ztx->posture_checks->must_send = true; //error, must try again
        } else {
            ztx->posture_checks->must_send = false; //did not error, can skip submissions
            handle_pr_resp_timer_events(ztx, pr_resp);
            ziti_services_refresh(ztx, true);
            ZTX_LOG(DEBUG, "done with bulk posture response submission");
        }
    }

    free_ziti_pr_response_ptr(pr_resp);
}

static void ziti_pr_set_info_errored(ziti_context ztx, const char *id) {
    model_map_set(&ztx->posture_checks->error_states, id, (void *) &IS_ERRORED);
}

static void ziti_pr_set_info_success(ziti_context ztx, const char *id) {
    model_map_set(&ztx->posture_checks->error_states, id, (void *) &IS_NOT_ERRORED);
}

static bool ziti_pr_is_info_errored(ziti_context ztx, const char *id) {
    bool *is_errored = model_map_get(&ztx->posture_checks->error_states, id);
    if (is_errored == NULL) {
        return false;
    }

    return *is_errored;
}

static void ziti_pr_send(ziti_context ztx) {
    ziti_pr_send_bulk(ztx);
}

static char* ziti_pr_to_json(const ziti_pr_base *pr) {
    const type_meta *meta = get_pr_req_meta(pr->typeId);
    size_t len;
    char *json = model_to_json(pr, meta, MODEL_JSON_COMPACT, &len);
    return json;
}

int model_list_fmt_to_json(string_buf_t *buf, model_list *l, const type_meta *meta, int flags, int indent);
static void ziti_pr_send_bulk(ziti_context ztx) {
    struct posture_checks *checks = ztx->posture_checks;
    if (!checks) {
        ZTX_LOG(DEBUG, "endpoint is disabled");
        return;
    }

    const char *key;
    pr_info *info;
    model_list send_prs = {};
    MODEL_MAP_FOREACH(key, info, &checks->responses) {
        ZTX_LOG(VERBOSE, "%s posture response [%s], pending = %s",
                info->should_send ? "sending" : "not sending",
                info->id, 
                info->pending ? "true" : "false");
        if (info->should_send) {
            model_list_append(&send_prs, info);
        }
    }

    if (model_list_size(&send_prs) > 0) {
        ZTX_LOG(DEBUG, "sending posture responses [%zd]", model_list_size(&send_prs));

        if (ztx->ctrl.is_ha) {
            send_posture_ha(ztx, &send_prs);
        } else {
            send_posture_legacy(ztx, &send_prs);
        }
    } else {
        ZTX_LOG(VERBOSE, "no change in posture data, not sending");
    }
    model_list_clear(&send_prs, NULL);
}

static void send_posture_legacy(ziti_context ztx, model_list *send_prs) {
    model_list json_list = {};
    pr_info *info;
    MODEL_LIST_FOREACH(info, *send_prs) {
        char *json = ziti_pr_to_json(info->obj);
        model_list_append(&json_list, json);
        info->should_send = false;
    }

    string_buf_t buf;
    string_buf_init(&buf);
    model_list_fmt_to_json(&buf, &json_list, get_json_meta(), 0, 0);
    model_list_clear(&json_list, free);

    size_t body_len;
    char *body = string_buf_to_string(&buf, &body_len);
    ZTX_LOG(TRACE, "bulk posture response: %s", body);

    ziti_pr_post_bulk(ztx_get_controller(ztx), body, body_len, ziti_pr_post_bulk_cb, ztx);
    free(body);
    string_buf_free(&buf);
}

static void send_posture_ha(ziti_context ztx, model_list *send_prs) {
    pr_info *info;
    Ziti__EdgeClient__Pb__PostureResponse *pr_resp;
    model_list process_list = {};
    model_list pb_list = {};
    MODEL_LIST_FOREACH(info, *send_prs) {
        switch (info->obj->typeId) {
            case ziti_posture_query_type_Unknown:
                break;
            case ziti_posture_query_type_PC_Domain: {
                ziti_pr_domain_req *req = (ziti_pr_domain_req *) info->obj;

                pr_resp = calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse));
                ziti__edge_client__pb__posture_response__init(pr_resp);
                Ziti__EdgeClient__Pb__PostureResponse__Domain * d = calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse__Domain));
                ziti__edge_client__pb__posture_response__domain__init(d);
                d->name = s_strdup(req->domain);
                pr_resp->type_case = ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_DOMAIN;
                pr_resp->domain = d;
                model_list_append(&pb_list, pr_resp);
                break;
            }
            case ziti_posture_query_type_PC_OS: {
                ziti_pr_os_req *req = (ziti_pr_os_req *) info->obj;
                Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem *os =
                        calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem));
                ziti__edge_client__pb__posture_response__operating_system__init(os);
                os->type = s_strdup(req->type);
                os->version = s_strdup(req->version);
                os->build = s_strdup(req->build);

                pr_resp = calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse));
                ziti__edge_client__pb__posture_response__init(pr_resp);
                pr_resp->type_case = ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_OS;
                pr_resp->os = os;
                model_list_append(&pb_list, pr_resp);
                break;
            }
            case ziti_posture_query_type_PC_Process: {
                ziti_pr_process_req *req = (ziti_pr_process_req *) info->obj;
                Ziti__EdgeClient__Pb__PostureResponse__Process *proc =
                        calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse__Process));
                ziti__edge_client__pb__posture_response__process__init(proc);
                proc->path = s_strdup(req->path);
                proc->hash = s_strdup(req->hash);
                proc->isrunning = req->is_running;
                model_list_append(&process_list, proc);
                break;
            }
            case ziti_posture_query_type_PC_Process_Multi:
                break;
            case ziti_posture_query_type_PC_MAC: {
                ziti_pr_mac_req *req = (ziti_pr_mac_req *) info->obj;
                Ziti__EdgeClient__Pb__PostureResponse__Macs *mac =
                        calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse__Macs));
                ziti__edge_client__pb__posture_response__macs__init(mac);
                mac->n_addresses = model_list_size(&req->mac_addresses);
                mac->addresses = calloc(mac->n_addresses, sizeof(mac->addresses[0]));
                int i = 0;
                const char* addr;
                MODEL_LIST_FOREACH(addr, req->mac_addresses) {
                    mac->addresses[i++] = s_strdup(addr);
                }

                pr_resp = calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse));
                ziti__edge_client__pb__posture_response__init(pr_resp);
                pr_resp->type_case = ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_MACS;
                pr_resp->macs = mac;
                model_list_append(&pb_list, pr_resp);
                break;
            }
            case ziti_posture_query_type_PC_MFA:
                break;
            case ziti_posture_query_type_PC_Endpoint_State: {
                ziti_pr_endpoint_state_req *req = (ziti_pr_endpoint_state_req *) info->obj;
                uv_timeval64_t now;
                uv_gettimeofday(&now);

                if (req->unlocked) {
                    Ziti__EdgeClient__Pb__PostureResponse__Unlocked *unlocked = calloc(1, sizeof(*unlocked));
                    ziti__edge_client__pb__posture_response__unlocked__init(unlocked);
                    unlocked->time = calloc(1, sizeof(*unlocked->time));
                    google__protobuf__timestamp__init(unlocked->time);
                    unlocked->time->seconds = now.tv_sec;

                    pr_resp = calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse));
                    ziti__edge_client__pb__posture_response__init(pr_resp);
                    pr_resp->type_case = ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_UNLOCKED;
                    pr_resp->unlocked = unlocked;
                    model_list_append(&pb_list, pr_resp);
                }

                if (req->woken) {
                    Ziti__EdgeClient__Pb__PostureResponse__Woken *woken = calloc(1, sizeof(*woken));
                    ziti__edge_client__pb__posture_response__woken__init(woken);
                    woken->time = calloc(1, sizeof(*woken->time));
                    google__protobuf__timestamp__init(woken->time);
                    woken->time->seconds = now.tv_sec;

                    pr_resp = calloc(1, sizeof(Ziti__EdgeClient__Pb__PostureResponse));
                    ziti__edge_client__pb__posture_response__init(pr_resp);
                    pr_resp->type_case = ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_WOKEN;
                    pr_resp->woken = woken;
                    model_list_append(&pb_list, pr_resp);
                }

                break;
            }
        }
    }

    if (model_list_size(&process_list) > 0) {
        pr_resp = calloc(1, sizeof(*pr_resp));
        ziti__edge_client__pb__posture_response__init(pr_resp);
        Ziti__EdgeClient__Pb__PostureResponse__ProcessList *pl = calloc(1, sizeof(*pl));
        ziti__edge_client__pb__posture_response__process_list__init(pl);
        pl->n_processes = model_list_size(&process_list);
        pl->processes = calloc(pl->n_processes, sizeof(pl->processes[0]));
        int i = 0;
        Ziti__EdgeClient__Pb__PostureResponse__Process *proc;
        MODEL_LIST_FOREACH(proc, process_list) {
            pl->processes[i++] = proc;
        }
        model_list_clear(&process_list, NULL);
        pr_resp->type_case = ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_PROCESS_LIST;
        pr_resp->processlist = pl;
        model_list_append(&pb_list, pr_resp);
    }

    if (model_list_size(&pb_list) > 0) {
        Ziti__EdgeClient__Pb__PostureResponses *resp = calloc(1, sizeof(*resp));
        ziti__edge_client__pb__posture_responses__init(resp);

        resp->n_responses = model_list_size(&pb_list);
        resp->responses = calloc(resp->n_responses, sizeof(resp->responses[0]));

        int idx = 0;
        MODEL_LIST_FOREACH(pr_resp, pb_list) {
            resp->responses[idx++] = pr_resp;
        }
        model_list_clear(&pb_list, NULL);

        uint8_t pad[128];
        ProtobufCBufferSimple buffer = PROTOBUF_C_BUFFER_SIMPLE_INIT(pad);
        ziti__edge_client__pb__posture_responses__pack_to_buffer(resp, (ProtobufCBuffer *) &buffer);
        ziti__edge_client__pb__posture_responses__free_unpacked(resp, NULL);
        ZTX_LOG(VERBOSE, "posture protobuf size = %zd", buffer.len);

        ziti_channel_t *ch;
        const char *n;
        MODEL_MAP_FOREACH(n, ch, &ztx->channels) {
            ziti_channel_update_posture(ch, buffer.data, buffer.len);
        }

        PROTOBUF_C_BUFFER_SIMPLE_CLEAR(&buffer);
    }
}

static void ziti_pr_handle_mac(ziti_context ztx, const char *id, char **mac_addresses, int num_mac) {
    ziti_pr_mac_req *mac_req = alloc_ziti_pr_mac_req();
    *mac_req = (ziti_pr_mac_req){
            .id = strdup(id),
            .typeId = ziti_posture_query_type_PC_MAC,
    };
    for (int idx = 0; idx < num_mac; idx++) {
        model_list_append(&mac_req->mac_addresses, strdup(mac_addresses[idx]));
    }

    ziti_collect_pr(ztx, mac_req);
}

static void ziti_pr_handle_domain(ziti_context ztx, const char *id, const char *domain) {
    ziti_pr_domain_req *req = alloc_ziti_pr_domain_req();
    *req = (ziti_pr_domain_req){
            .id = strdup(id),
            .domain = strdup(domain),
            .typeId = ziti_posture_query_type_PC_Domain,
    };

    ziti_collect_pr(ztx, req);
}

static void ziti_pr_handle_os(ziti_context ztx, const char *id, const char *os_type, const char *os_version, const char *os_build) {
    ziti_pr_os_req *os_req = alloc_ziti_pr_os_req();
    *os_req = (ziti_pr_os_req){
            .id = strdup(id),
            .typeId = ziti_posture_query_type_PC_OS,
            .type = strdup(os_type),
            .version = strdup(os_version),
            .build = strdup(os_build)
    };
    
    ziti_collect_pr(ztx, os_req);
}


static void ziti_pr_handle_process(ziti_context ztx, const char *id, const char *path,
                                   bool is_running, const char *sha_512_hash, char **signers,
                                   int num_signers) {

    ziti_pr_process_req *process_req = alloc_ziti_pr_process_req();
    *process_req = (ziti_pr_process_req){
            .id = strdup(id),
            .typeId = ziti_posture_query_type_PC_Process,
            .path = strdup(path),
            .is_running = is_running,
            .hash = sha_512_hash ? strdup(sha_512_hash) : NULL,
    };
    for (int idx = 0; idx < num_signers; idx++) {
        model_list_append(&process_req->signers, strdup(signers[idx]));
    }
    
    ziti_collect_pr(ztx, process_req);
}

#if _WIN32
typedef NTSTATUS (NTAPI *sRtlGetVersion)
        (PRTL_OSVERSIONINFOW lpVersionInformation);

static sRtlGetVersion get_win32_version_f() {
    static sRtlGetVersion s_func;
    if (s_func == NULL) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        s_func = (sRtlGetVersion) GetProcAddress(ntdll, "RtlGetVersion");
    }
    return s_func;
}
static

#endif // _WIN32

void default_pq_os(ziti_context ztx, const char *id, ziti_pr_os_cb response_cb) {
    const char *os;
    const char *ver;
    const char *build;
#if _WIN32
    OSVERSIONINFOEXW os_info = {0};
    os_info.dwOSVersionInfoSize = sizeof(os_info);
    sRtlGetVersion version_f = get_win32_version_f();
    if (version_f) {
        version_f((PRTL_OSVERSIONINFOW) &os_info);
    } else {
        /* Silence GetVersionEx() deprecation warning. */
#pragma warning(suppress : 4996)
        GetVersionExW((LPOSVERSIONINFOW) &os_info);
    }

    switch (os_info.wProductType) {
        case 1:
            os = "windows";
            break;
        case 2:
        case 3:
            os = "windowsserver";
            break;
        default:
            os = "<unknown windows type>";
    }
    char winver[16];
    sprintf_s(winver, 16, "%d.%d.%d", os_info.dwMajorVersion, os_info.dwMinorVersion, os_info.dwBuildNumber);
    ver = winver;
    build = "ununsed";
#else
    const ziti_env_info *info = get_env_info();
    os = info->os;
    ver = info->os_release;
    build = info->os_version;
#endif

    response_cb(ztx, id, os, ver, build);
}

static bool non_zero_addr(const char *addr, int addr_size) {
    for (int i = 0; i < addr_size; i++) {
        if (addr[i] != 0) return true;
    }
    return false;
}

static void default_pq_mac(ziti_context ztx, const char *id, ziti_pr_mac_cb response_cb) {

    uv_interface_address_t *info;
    int count;
    uv_interface_addresses(&info, &count);

    model_map addrs = {0};

    int addr_size = sizeof(info[0].phys_addr);
    for (int i = 0; i < count; i++) {
        if (!info[i].is_internal && non_zero_addr(info[i].phys_addr, addr_size)) {
            if (model_map_get(&addrs, info[i].name) == NULL) {
                char *mac;
                hexify((const uint8_t *) info[i].phys_addr, addr_size, ':', &mac);
                model_map_set(&addrs, info[i].name, mac);
            }
        }
    }

    size_t addr_count = model_map_size(&addrs);
    char **addresses = calloc(addr_count, sizeof(char *));
    const char *ifname;
    char *mac;
    int idx = 0;
    MODEL_MAP_FOREACH(ifname, mac, &addrs) {
        addresses[idx++] = mac;
    }

    response_cb(ztx, id, addresses, (int) addr_count);
    free(addresses);
    model_map_clear(&addrs, free);
    uv_free_interface_addresses(info, count);
}


static void default_pq_domain(ziti_context ztx, const char *id, ziti_pr_domain_cb cb) {
#if _WIN32
    uint32_t status;
    LPWSTR buf;
    NetGetJoinInformation(NULL, &buf, &status);
    char domain[256];
    sprintf_s(domain, sizeof(domain), "%ls", buf);
    cb(ztx, id, domain);
    NetApiBufferFree(buf);
#else
    cb(ztx, id, "");
#endif
}

static void process_check_work(uv_work_t *w);

static void process_check_done(uv_work_t *w, int status) {
    struct process_work *pcw = container_of(w, struct process_work, w);
    if (!pcw->canceled) {
        model_map_remove_key(&pcw->ztx->posture_checks->active_work, &pcw, sizeof(uintptr_t));
        pcw->cb(pcw->ztx, pcw->id, pcw->path, pcw->is_running, pcw->sha512, pcw->signers, pcw->num_signers);
    } else {
        ZITI_LOG(INFO, "process check path[%s] was cancelled", pcw->path);
    }
    free(pcw->id);
    free(pcw->path);
    FREE(pcw->sha512);
    if (pcw->signers) {
        for (int i = 0; i < pcw->num_signers; i++) {
            free(pcw->signers[i]);
        }
        free(pcw->signers);
    }
    free(pcw);
}

bool ziti_service_has_query_with_timeout(ziti_service *service) {
    ziti_posture_query_set *current_set = NULL;
    model_map_iter it = model_map_iterator(&service->posture_query_map);
    while (it != NULL) {
        current_set = model_map_it_value(it);

        ziti_posture_query *current_query = current_set->posture_queries[0];
        for (int posture_query_idx = 1; current_query != NULL; posture_query_idx++) {

            if (current_query->timeout != NO_TIMEOUTS) {
                return true;
            }

            current_query = current_set->posture_queries[posture_query_idx];
        }

        it = model_map_it_remove(it);
    }

    return false;
}

static void default_pq_process(ziti_context ztx, const char *id, const char *path, ziti_pr_process_cb cb) {
    NEWP(wr, struct process_work);
    wr->id = strdup(id);
    wr->path = strdup(path);
    wr->cb = cb;
    wr->ztx = ztx;
    model_map_set_key(&ztx->posture_checks->active_work, &wr, sizeof(uintptr_t), wr);
    uv_queue_work(ztx->loop, &wr->w, process_check_work, process_check_done);
}

static void process_check_work(uv_work_t *w) {
    struct process_work *pcw = container_of(w, struct process_work, w);
    ziti_context ztx = pcw->ztx;
    const char *path = pcw->path;

    unsigned char *digest;
    size_t digest_len;
    uv_fs_t file;
    int rc = uv_fs_stat(w->loop, &file, path, NULL);
    if (rc != 0) {
        return;
    }

    pcw->is_running = check_running(w->loop, path);
    if (hash_sha512(ztx, w->loop, path, &digest, &digest_len) == 0) {
        hexify(digest, digest_len, 0, &pcw->sha512);
        ZITI_LOG(VERBOSE, "file(%s) hash = %s", path, pcw->sha512);
        free(digest);
    }
    pcw->signers = get_signers(path, &pcw->num_signers);
}

void ziti_endpoint_state_pr_cb(ziti_pr_response *pr_resp, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    if (err) {
        ZTX_LOG(ERROR, "error during endpoint state posture response submission: %d - %s",
                (int)err->http_code, err->message);
    } else {
        ZTX_LOG(INFO, "endpoint state sent");
        handle_pr_resp_timer_events(ztx, pr_resp);
        ziti_services_refresh(ztx, true);
    }
    free_ziti_pr_response_ptr(pr_resp);
}


void ziti_endpoint_state_change(ziti_context ztx, bool woken, bool unlocked) {
    if (!ztx->posture_checks) {
        ZTX_LOG(WARN, "endpoint is disabled");
        return;
    }

    if (woken || unlocked) {
        ZTX_LOG(INFO, "endpoint state change reported: woken[%s] unlocked[%s]", woken ? "TRUE":"FALSE", unlocked ? "TRUE":"FALSE");
        ziti_pr_endpoint_state_req state_req = {
                .id = "0",
                .typeId = ziti_posture_query_type_PC_Endpoint_State,
                .unlocked = unlocked,
                .woken = woken
        };

        size_t obj_len;

        char *obj = ziti_pr_endpoint_state_req_to_json(&state_req, 0, &obj_len);
        ziti_pr_post(ztx_get_controller(ztx), obj, obj_len, ziti_endpoint_state_pr_cb, ztx);
        FREE(obj);
    } else {
        ZTX_LOG(INFO, "endpoint state change reported, but no reason to send data: woken[%s] unlocked[%s]", woken ? "TRUE":"FALSE", unlocked ? "TRUE":"FALSE");
    }
}


static int hash_sha512(ziti_context ztx, uv_loop_t *loop, const char *path, unsigned char **out_buf, size_t *out_len) {
    size_t digest_size = crypto_hash_sha512_bytes();
    unsigned char *digest = NULL;
    int rc = 0;

#define CHECK(op) do{ rc = (op); if (rc != 0) { \
ZITI_LOG(ERROR, "failed hashing path[%s] op[" #op "]: %d", path, rc); \
goto cleanup;                                   \
} }while(0)

    uv_fs_t ft;
    uv_file file = uv_fs_open(loop, &ft, path, UV_FS_O_RDONLY, 0, NULL);

    if (file < 0) { return -1; }
    uv_buf_t buf = uv_buf_init(malloc(64 * 1024), 64 * 1024);
    int64_t offset = 0;
    crypto_hash_sha512_state sha512;
    crypto_hash_sha512_init(&sha512);

    // hash data
    while (true) {
        int read = uv_fs_read(loop, &ft, file, &buf, 1, offset, NULL);
        if (read == 0) {
            break;
        }

        if (read < 0) {
            rc = -1;
            goto cleanup;
        }

        offset += read;
        CHECK(crypto_hash_sha512_update(&sha512, (uint8_t *) buf.base, read));
    }
    digest = malloc(digest_size);
    CHECK(crypto_hash_sha512_final(&sha512, digest));

    *out_buf = digest;
    *out_len = digest_size;

    cleanup:
    if (rc != 0) FREE(digest);
    uv_fs_close(loop, &ft, file, NULL);
    uv_fs_req_cleanup(&ft);
    FREE(buf.base);

    return rc;
}

static bool check_running(uv_loop_t *loop, const char *path) {
    bool result = false;
#if _WIN32
    HANDLE sh = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (sh == INVALID_HANDLE_VALUE) {
        ZITI_LOG(ERROR, "failed to get process list: %lu", GetLastError());
        return result;
    }

    // Set the size of the structure before using it.
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    // Retrieve information about the first process, and exit if unsuccessful
    if( !Process32First( sh, &pe32 ) )
    {
        CloseHandle( sh );          // clean the snapshot object
        return( FALSE );
    }

    char fullPath[1024];
    DWORD fullPathSize;

    // Now walk the snapshot of processes, and display information about each process in turn
    ZITI_LOG(VERBOSE, "checking to see if process is running: %s", path);
    do
    {
        ZITI_LOG(VERBOSE, "process is running: %s", pe32.szExeFile);

        HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (ph == NULL) {
            if (pe32.th32ProcessID > 0) {
                ZITI_LOG(DEBUG, "process %s is running, however not able to open handle. GetLastError(): %lu", pe32.szExeFile, GetLastError());
            }
            continue;
        }
        fullPathSize = sizeof(fullPath);
        QueryFullProcessImageNameA(ph, 0, fullPath, &fullPathSize);
        CloseHandle(ph);

        ZITI_LOG(VERBOSE, "comparing process: %s to: %.*s", pe32.szExeFile, fullPathSize, fullPath);
        if (strnicmp(path, fullPath, fullPathSize) == 0) {
            result = true;
            break;
        }
    } while( Process32Next( sh, &pe32 ) );

    CloseHandle(sh);

#elif __linux || __linux__

    uv_fs_t fs_proc;
    uv_fs_scandir(loop, &fs_proc, "/proc", 0, NULL);
    uv_dirent_t de;
    uv_fs_t ex;
    char proc_path[128];
    while (!result && uv_fs_scandir_next(&fs_proc, &de) != UV_EOF) {
        if (de.type == UV_DIRENT_DIR) {
            snprintf(proc_path, sizeof(proc_path), "/proc/%s/exe", de.name);
            if (uv_fs_readlink(loop, &ex, proc_path, NULL) == 0) {
                if (strcmp((const char *) ex.ptr, path) == 0) {
                    result = true;
                }
                free(ex.ptr);
            }
        }
    }
    uv_fs_req_cleanup(&fs_proc);

#elif __APPLE__ && TARGET_OS_IPHONE == 0 && TARGET_OS_SIMULATOR == 0
    int n_pids = proc_listallpids(NULL, 0);
    unsigned long pids_sz = sizeof(pid_t) * (unsigned long)n_pids;
    pid_t * pids = calloc(1, pids_sz);
    proc_listallpids(pids, (int)pids_sz);
    char proc_path[PROC_PIDPATHINFO_MAXSIZE];
    for (int i=0; i < n_pids; i++) {
        if (pids[i] == 0) continue;
        proc_pidpath(pids[i], proc_path, sizeof(proc_path)); // returns strlen(proc_path)
        if (strncasecmp(proc_path, path, sizeof(proc_path)) == 0) {
            result = true;
            break;
        }
    }
    free(pids);
#else
    uv_utsname_t uname;
    uv_os_uname(&uname);
    ZITI_LOG(WARN, "not implemented on %s", uname.sysname);
#endif
    ZITI_LOG(DEBUG, "is running result: %s for %s", (result ? "true" : "false"), path);
    return result;
}

char **get_signers(const char *path, int *signers_count) {
    char **result = NULL;
#if _WIN32
    WCHAR filename[MAX_PATH];
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL res;
    DWORD dwEncoding, dwContentType, dwFormatType;

    size_t conv;
    mbstowcs_s(&conv, filename, MAX_PATH, path, MAX_PATH);

    res = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                           filename,
                           CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                           CERT_QUERY_FORMAT_FLAG_BINARY,
                           0,
                           &dwEncoding,
                           &dwContentType,
                           &dwFormatType,
                           &hStore,
                           &hMsg,
                           NULL);

    if (!res) return NULL;

    result = calloc(16, sizeof(char *));
    int idx = 0;
    pCertContext = CertEnumCertificatesInStore(hStore, NULL);
    while (pCertContext != NULL) {
        BYTE sha1[20];
        char *hex;
        DWORD size = sizeof(sha1);
        BOOL rc = CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, sha1, &size);
        if (!rc) {
            ZITI_LOG(WARN, "failed to get cert[%d] sig: %lu", idx, GetLastError());
            continue;
        } else {
            hexify(sha1, sizeof(sha1), 0, &hex);
            ZITI_LOG(VERBOSE, "%s cert[%d] sig = %s", path, idx, hex);

        }
        pCertContext = CertEnumCertificatesInStore(hStore, pCertContext);
        result[idx++] = hex;
    }
    *signers_count = idx;

#else
    *signers_count = 0;
#endif
    return result;
}
