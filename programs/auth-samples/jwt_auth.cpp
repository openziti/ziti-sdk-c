/*
 Copyright 2024 NetFoundry Inc.

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

//
// Created by Eugene Kobyakov on 8/27/24.
//
#include <uv.h>
#include "tlsuv/tlsuv.h"
#include "tlsuv/http.h"

#include <csignal>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <CLI/CLI.hpp>
#include "ziti/ziti_model.h"
#include "ziti/ziti.h"
#include "ziti/ziti_log.h"

struct prompt_work {
    uv_work_t w{};
    std::string prompt;
    std::string result;

    void *data;
    void (*cb)(ziti_context, const std::string&, void *data);
};

static void prompt_w(prompt_work *w) {
    std::cout << w->prompt;
    std::cin >> w->result;
}

static void prompt_d(prompt_work *w, int status) {
    w->cb(static_cast<ziti_context>(w->w.data), w->result, w->data);
    delete w;
}

static void prompt(ziti_context z, const std::string &prompt, void *data,
                   void (*cb)(ziti_context, const std::string &resp, void *)){
    auto l = (uv_loop_t *)ziti_app_ctx(z);
    auto work = new prompt_work;
    work->prompt = prompt;
    work->cb = cb;
    work->data = data;
    work->w.data = z;
    uv_queue_work(l, (uv_work_t*)work,
                  reinterpret_cast<uv_work_cb>(prompt_w),
                  reinterpret_cast<uv_after_work_cb>(prompt_d));
}


static void on_auth_event(ziti_context ztx, const ziti_auth_event &ev) {
    switch (ev.action) {
        case ziti_auth_prompt_totp:
            break;
        case ziti_auth_prompt_pin:
            break;
        case ziti_auth_select_external: {
            std::stringstream pr;
            int i;
            auto ids = new std::vector<std::string>;
            for (i = 0; ev.providers[i] != nullptr; i++) {
                auto p = ev.providers[i];
                ids->push_back(p->name);
                pr << i << ": " << p->name << " " << p->provider_url << std::endl;
            }
            pr << "Select provider(0-" << (i-1) << "): ";
            prompt(ztx, pr.str(), ids, [](ziti_context z, const std::string &res, void *data){
                auto ids = (std::vector<std::string>*)data;
                auto idx = stoi(res);
                auto id = (*ids)[idx];
                auto rc = ziti_use_ext_jwt_signer(z, id.c_str());
                if (rc != ZITI_OK) {
                    std::cerr << "failed to select provider: " << ziti_errorstr(rc) << std::endl;
                }
                delete ids;
            });
            break;
        }
        case ziti_auth_login_external: {
            ziti_ext_auth(ztx, [](ziti_context ztx, const char *url, void*){
                std::cout << "continue auth: " << url << std::endl;
            }, ztx);
            break;
        }
    }
}

static void event_handler(ziti_context ztx, const ziti_event_t *ev){
    switch (ev->type) {
        case ZitiContextEvent: {
            const ziti_context_event &event = ev->ctx;
            std::cout << "ztx status: " << ziti_errorstr(event.ctrl_status) << std::endl;
            break;
        }
        case ZitiAuthEvent:
            on_auth_event(ztx, ev->auth);
            break;
        case ZitiRouterEvent:
        case ZitiServiceEvent:
        case ZitiAPIEvent:
            break;
    }
}

static std::string getCAbundle(uv_loop_t *l, const std::string &ctrl) {
    auto bootstrapTLS = default_tls_context("", 0);
    bootstrapTLS->set_cert_verify(bootstrapTLS,
                                  [](const tlsuv_certificate_s*, void*) {
                                      return 0;
                                  }, nullptr);

    tlsuv_http_t clt{};
    tlsuv_http_init(l, &clt, ctrl.c_str());
    tlsuv_http_set_ssl(&clt, bootstrapTLS);
    std::string pkcs7;
    tlsuv_http_req(&clt, "GET", "/.well-known/est/cacerts",
                   [](tlsuv_http_resp_t *resp, void *ctx ){
                       if (resp->code != 200) {
                           std::cerr << "failed to get CA bundler from controller: "
                                     << resp->code << ' '
                                     << resp->status << std::endl;
                           exit(1);
                       }
                       resp->body_cb = [](tlsuv_http_req_t *r, char *body, ssize_t len){
                           auto str = (std::string*)r->data;
                           if (len > 0)
                               str->append(body, len);
                       };
                   }, &pkcs7);

    uv_run(l, UV_RUN_DEFAULT);

    tlsuv_certificate_t chain = nullptr;
    bootstrapTLS->parse_pkcs7_certs(&chain, pkcs7.c_str(), pkcs7.length());

    char *pem = nullptr;
    size_t pem_len = 0;
    chain->to_pem(chain, 1, &pem, &pem_len);

    std::string ca_bundle(pem, pem_len);
    free(pem);
    chain->free(chain);
    tlsuv_http_close(&clt, nullptr);
    uv_run(l, UV_RUN_DEFAULT);
    bootstrapTLS->free_ctx(bootstrapTLS);
    return ca_bundle;
}

int main(int argc, char *argv[]) {
    CLI::App app("ziti-sdk JWT authentication sample");
    std::string ctrl;
    int log_level;
    app.add_option("controller", ctrl, "ziti controller address")->required(true);
    app.add_option("-d,--debug", log_level, "set log level")->default_val(1);

    CLI11_PARSE(app, argc, argv);

    auto loop = uv_loop_new();
    auto ca = getCAbundle(loop, ctrl);
    ziti_config cfg{
            .controller_url = ctrl.c_str(),
            .id = {
                    .ca = ca.c_str(),
            }
    };
    ziti_options opts {
        .app_ctx = loop,
        .events = (unsigned int)-1,
        .event_cb = event_handler,
    };
    ziti_log_init(loop, log_level, NULL);
    ziti_context ztx;
    ziti_context_init(&ztx, &cfg);
    ziti_context_set_options(ztx, &opts);
    ziti_context_run(ztx, loop);
    uv_run(loop, UV_RUN_DEFAULT);
}