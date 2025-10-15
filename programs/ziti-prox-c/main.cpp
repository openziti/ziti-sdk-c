// Copyright (c) 2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include <CLI/CLI.hpp>

#if _WIN32
#include <winsock2.h>
#include <windows.h>
#include <shlwapi.h>
#define basename(p) PathFindFileName(p)
#else
#include <libgen.h>
#endif


#include "ziti/ziti.h"
#include "proxy.h"

class Run: public CLI::App {
public:

    Run(): App("run proxy", "run"),
           debug(2) {
        add_option("--debug,-d", debug, "log level");
        add_option("--identity,-i", identity, "identity config")->required();
        add_option("listener", intercepts, "<name:port>");
        add_option("--bind,-b", bindings, "bind service <name:host:port>");
        add_option("--bind-udp,-B", udp_bindings, "bind udp service <name:host:port>");
        add_option("--proxy,-p", proxy, "proxy url");

        final_callback([this] {
            this->execute();
        });
    }


private:
    int debug;
    std::string identity;
    std::vector<std::string> intercepts;
    std::vector<std::string> bindings;
    std::vector<std::string> udp_bindings;
    std::string proxy;

    void execute() const {
        run_opts opts{};
        opts.identity = this->identity.c_str();
        opts.debug = this->debug;
        for (auto &intercept: this->intercepts) {
            model_list_append(&opts.intercepts, intercept.c_str());
        }
        for (auto &binding: this->bindings) {
            model_list_append(&opts.bindings, binding.c_str());
        }
        for (auto &udp: this->udp_bindings) {
            model_list_append(&opts.udp_bindings, udp.c_str());
        }
        if (!proxy.empty()) opts.proxy = this->proxy.c_str();
        int rc = run_proxy(&opts);
        ::exit(rc);
    }
};

int main(int argc, char *argv[]) {
    const char *name = basename(argv[0]);
    CLI::App app{name};
    ziti_set_app_info(name, ziti_get_version()->revision);
    bool verbose = false;
    auto ver = app.add_subcommand("version", "print version information");
    ver->add_flag("--verbose,-v", verbose, "verbose output");
    ver->final_callback([&verbose] {
        std::cout << ziti_get_version()->version << std::endl;
        if (verbose) {
            std::cout << ziti_get_version()->revision << std::endl
                    << ziti_get_version()->build_date << std::endl;
        }
    });

    app.add_subcommand(std::make_shared<Run>());
    app.require_subcommand(1);
    CLI11_PARSE(app, argc, argv);
    return 0;
}

