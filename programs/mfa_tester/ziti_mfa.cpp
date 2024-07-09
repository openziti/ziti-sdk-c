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

#include <CLI/CLI.hpp>

#include <cassert>
#include <iostream>
#include <mutex>

#include <uv.h>

#include "ziti/ziti.h"
#include "ziti/ziti_log.h"

typedef void(*prompt_cb)(ziti_context, const char *input);
static std::string identity;
static uv_loop_t *loop = uv_default_loop();

struct prompt_req {
    uv_work_t req{};
    std::string prompt;
    std::string input;
    prompt_cb cb{};
    std::mutex lock;
};

static void prompt_work(uv_work_t *req) {
    auto pr = (prompt_req *) req;
    std::cout << pr->prompt << ": ";
    std::getline(std::cin, pr->input);
}

static void prompt_done(uv_work_t *req, int status) {
    auto pr = (prompt_req *) req;
    auto input = pr->input;
    auto cb = pr->cb;

    pr->lock.unlock();

    cb((ziti_context) req->data, input.c_str());
}


static void ztx_prompt(ziti_context ztx, const std::string &prompt, void(*cb)(ziti_context, const char *input)) {
    static prompt_req req;
    auto lock = req.lock.try_lock();
    assert(lock);

    req.prompt = prompt;
    req.input.clear();
    req.cb = cb;
    req.req.data = ztx;
    uv_queue_work(loop, (uv_work_t *) &req, prompt_work, prompt_done);
}


#define CHECK(op) do { \
auto rc = op; \
if (rc != ZITI_OK)                   \
std::cerr << "ERROR: " << rc << "/" << ziti_errorstr(rc) << std::endl; \
} while(0)

static void on_enroll(ziti_context ztx, int status, ziti_mfa_enrollment *info, void *data) {
    if (info) {
        printf("\nMFA enrollment: \n"
               "verified: %d\n"
               "url: %s\n", info->is_verified, info->provisioning_url);

        if (!info->is_verified) {
            ztx_prompt(ztx, "verify", [](ziti_context ztx, const char *code) {
                ziti_mfa_verify(ztx, (char *) code, [](ziti_context ztx, int status, void *) {
                    if (status == ZITI_OK) {
                        printf("MFA Verify success!\n");
                    } else {
                        fprintf(stderr, "failed to verify: %d/%s\n", status, ziti_errorstr(status));
                    }
                    ziti_shutdown(ztx);
                }, nullptr);
            });
        }
    } else {
        std::cerr << "enroll status: " << status << "/" << ziti_errorstr(status) << std::endl;
    }
}


static void base_run(void(*handler)(ziti_context, const ziti_event_t *)) {
    ziti_config config = {nullptr};
    ziti_context ztx = nullptr;

    ziti_options opts = {
            .app_ctx = (void *) (handler),
            .events = ZitiContextEvent | ZitiMfaAuthEvent,
            .event_cb = handler,
    };
    std::cerr << std::endl;

    CHECK(ziti_load_config(&config, identity.c_str()));
    CHECK(ziti_context_init(&ztx, &config));

    CHECK(ziti_context_set_options(ztx, &opts));
    CHECK(ziti_context_run(ztx, loop));

    std::cout << "starting event loop" << std::endl;
    uv_run(loop, UV_RUN_DEFAULT);

}

static void get_codes() {
    base_run([](ziti_context ztx, const ziti_event_t *ev) {
        switch (ev->type) {
            case ZitiContextEvent: {
                const ziti_context_event &e = ev->ctx;
                if (e.ctrl_status == ZITI_PARTIALLY_AUTHENTICATED) {
                    std::cout << "enrolled in MFA" << std::endl;
                } else if (e.ctrl_status == ZITI_OK) {
                    std::cout << "auth SUCCESS" << std::endl;
                } else {
                    std::cout << e.err << std::endl;
                }
                break;
            }
            case ZitiMfaAuthEvent: {
                const ziti_mfa_auth_event &e = ev->mfa_auth_event;
                std::string prompt = std::string("enter ") + e.auth_query_mfa->type_id + "/" +
                                     e.auth_query_mfa->provider + " code";
                ztx_prompt(ztx, prompt, [](ziti_context z, const char *code) {
                    ziti_mfa_auth(z, code, [](ziti_context z, int status, void *) {
                        if (status == ZITI_OK) {
                            std::cout << "MFA auth success!" << std::endl;
                            ztx_prompt(z, "enter MFA code", [](ziti_context z, const char *code) {
                                ziti_mfa_get_recovery_codes(z, code, [](ziti_context z, int status, char **codes, void *) {
                                    if (status == ZITI_OK) {
                                        for(int i = 0; codes && codes[i]; i++) {
                                            std::cout << codes[i] << std::endl;
                                        }
                                    } else {
                                        std::cout << "MFA auth failed: " << status << '/' << ziti_errorstr(status) << std::endl;
                                    }
                                    ziti_shutdown(z);
                                }, nullptr);
                            });

                        } else {
                            std::cout << "MFA auth failed: " << status << '/' << ziti_errorstr(status) << std::endl;
                        }
                    }, nullptr);
                });

                break;
            }
            default:
                std::cout << "unhandled event" << std::endl;
        }
    });
}

static void test_mfa() {
    base_run([](ziti_context ztx, const ziti_event_t *ev) {
        switch (ev->type) {
            case ZitiContextEvent: {
                const ziti_context_event &e = ev->ctx;
                if (e.ctrl_status == ZITI_PARTIALLY_AUTHENTICATED) {
                    std::cout << "enrolled in MFA" << std::endl;
                } else if (e.ctrl_status == ZITI_OK) {
                    std::cout << "auth SUCCESS" << std::endl;
                    ziti_shutdown(ztx);
                } else {
                    std::cout << e.err << std::endl;
                }
                break;
            }
            case ZitiMfaAuthEvent: {
                const ziti_mfa_auth_event &e = ev->mfa_auth_event;
                std::string prompt = std::string("enter ") + e.auth_query_mfa->type_id + "/" +
                                     e.auth_query_mfa->provider + " code";
                ztx_prompt(ztx, prompt, [](ziti_context z, const char *code) {
                    ziti_mfa_auth(z, code, [](ziti_context z, int status, void *) {
                        if (status == ZITI_OK) {
                            std::cout << "MFA auth success!" << std::endl;
                        } else {
                            std::cout << "MFA auth failed: " << status << '/' << ziti_errorstr(status) << std::endl;
                        }
                    }, nullptr);
                });
                break;
            }
            default:
                std::cout << "unhandled event" << std::endl;
        }

    });
}

static void enroll_mfa() {
    std::cout << "enrolling identity: " << identity << std::endl;
    base_run([](ziti_context ztx, const ziti_event_t *ev) {
        switch (ev->type) {
            case ZitiContextEvent: {
                const ziti_context_event &e = ev->ctx;
                if (e.ctrl_status == ZITI_PARTIALLY_AUTHENTICATED) {
                    std::cout << "already enrolled in MFA" << std::endl;
                } else if (e.ctrl_status == ZITI_OK) {
                    ztx_prompt(ztx, "are you sure[y/N]?", [](ziti_context z, const char *resp) {
                        if (tolower(resp[0]) == 'y') {
                            ziti_mfa_enroll(z, on_enroll, nullptr);
                        }
                    });
                } else {
                    std::cout << e.err << std::endl;
                }
                break;
            }
            case ZitiMfaAuthEvent: {
                const ziti_mfa_auth_event &e = ev->mfa_auth_event;
                std::cout << "details: " << e.auth_query_mfa->type_id << "/"
                          << (e.auth_query_mfa->provider) << std::endl;
                ziti_shutdown(ztx);
                break;
            }
            default:
                std::cout << "unhandled event" << std::endl;
        }
    });
}

static void delete_mfa() {
    base_run([](ziti_context ztx, const ziti_event_t *ev){
        switch (ev->type) {
            case ZitiContextEvent: {
                const ziti_context_event &e = ev->ctx;
                if (e.ctrl_status == ZITI_PARTIALLY_AUTHENTICATED) {
                    std::cout << "enrolled in MFA" << std::endl;
                } else if (e.ctrl_status == ZITI_OK) {
                    std::cout << "auth SUCCESS" << std::endl;
                    ztx_prompt(ztx, "enter MFA code to remove", [](ziti_context z, const char *code){
                        ziti_mfa_remove(z, code, [](ziti_context z, int status, void *ctx){
                            std::cout << "remove status: " << ziti_errorstr(status) << std::endl;
                            ziti_shutdown(z);
                        }, nullptr);
                    });
                } else {
                    std::cout << e.err << std::endl;
                }
                break;
            }
            case ZitiMfaAuthEvent: {
                const ziti_mfa_auth_event &e = ev->mfa_auth_event;
                std::string prompt = std::string("enter ") + e.auth_query_mfa->type_id + "/" +
                                     e.auth_query_mfa->provider + " code";
                ztx_prompt(ztx, prompt, [](ziti_context z, const char *code) {
                    ziti_mfa_auth(z, code, [](ziti_context z, int status, void *) {
                        if (status == ZITI_OK) {
                            std::cout << "MFA auth success!" << std::endl;
                        } else {
                            std::cout << "MFA auth failed: " << status << '/' << ziti_errorstr(status) << std::endl;
                    }
                    }, nullptr);
                });
                break;
            }
            default:
                std::cout << "unhandled event" << std::endl;
        }
    });
}

std::ofstream logfile("/tmp/ziti_mfa", std::ios::ate);
const char *lbl[] = {
        "E", "W", "I", "D", "V", "T",
};

static void logger(int level, const char *loc, const char *msg, size_t msglen) {
    logfile << lbl[level] << ": " << loc << " " << std::string(msg, msglen) << std::endl;
}

int main(int argc, char *argv[]) {
    CLI::App app("ziti MFA test program", "ziti_mfa");

    ziti_log_init(loop, 3, logger);
    app.add_option("-i,--identity", identity, "ziti identity")->required()->check(CLI::ExistingFile);

    app.add_subcommand("enroll", "enroll identity to MFA")->final_callback(enroll_mfa);
    app.add_subcommand("test", "test MFA code auth")->final_callback(test_mfa);
    app.add_subcommand("codes", "get recovery codes")->final_callback(get_codes);
    app.add_subcommand("delete", "remove MFA enrollment")->final_callback(delete_mfa);

    app.require_subcommand(1);
    CLI11_PARSE(app, argc, argv);
}