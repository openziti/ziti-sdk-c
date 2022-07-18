// Copyright (c) 2022.  NetFoundry Inc.
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

#include <iostream>


#define  _GNU_SOURCE

#include <dlfcn.h>
#include <sys/socket.h>
#include <ziti/zitilib.h>
#include <uv.h>
#include "ziti/model_collections.h"


typedef int (*syscall_f_t)(long sysno, ...);

typedef int (*socket_f_t)(int, int, int);

typedef int (*connect_f_t)(int, const struct sockaddr *, socklen_t);

typedef int (*bind_f_t)(int, const struct sockaddr *, socklen_t);

typedef int (*getaddrinfo_f_t)(const char *__restrict __name,
                               const char *__restrict __service,
                               const struct addrinfo *__restrict __req,
                               struct addrinfo **__restrict __pai);

typedef int (*getsockopt_f_t)(int fd, int level, int optname, void *__restrict __optval,
                              socklen_t *__restrict __optlen);

static uv_once_t zitiy_init;
static uv_once_t load_once;

syscall_f_t syscall_f;
connect_f_t connect_f;
socket_f_t socket_f;
bind_f_t bind_f;
getaddrinfo_f_t getaddrinfo_f;
getsockopt_f_t getsockopt_f;

static void load_identities() {
    Ziti_lib_init();

    const char *env_str = getenv("ZITI_IDENTITIES");
    if (env_str == nullptr) { return; }

    std::string ids(env_str);
    size_t pos;
    do {
        pos = ids.find(';');
        auto id = ids.substr(0, pos);
        Ziti_load_context(id.c_str());
        ids.erase(0, pos + 1);
    } while (pos != std::string::npos);
}

static void lazy_load() {
    uv_once(&load_once, load_identities);
}

static void do_init() {
    socket_f = (socket_f_t) dlsym(RTLD_NEXT, "socket");
    connect_f = (connect_f_t) dlsym(RTLD_NEXT, "connect");
    bind_f = (bind_f_t) dlsym(RTLD_NEXT, "bind");
    getaddrinfo_f = (getaddrinfo_f_t) dlsym(RTLD_NEXT, "getaddrinfo");
    getsockopt_f = (getsockopt_f_t) dlsym(RTLD_NEXT, "getsockopt");
    syscall_f = (syscall_f_t) dlsym(RTLD_NEXT, "syscall");
}

static void zitify() {
    uv_once(&zitiy_init, do_init);
    Ziti_lib_init();

}

extern "C" {
uv_thread_t Ziti_lib_thread();
const char *Ziti_lookup(in_addr_t addr);
int Ziti_resolve(const char *host, const char *port, const struct addrinfo *addr, struct addrinfo **addrlist);
}

class Zitifier {
public:
    Zitifier() {
        zitify();
        lazy_load();
    }
};

static Zitifier loader;

int getaddrinfo(const char *__restrict name,
                const char *__restrict service,
                const struct addrinfo *__restrict hints,
                struct addrinfo **__restrict pai) {
    int rc = Ziti_resolve(name, service, hints, pai);
    if (rc != 0) {
        rc = getaddrinfo_f(name, service, hints, pai);
    }

    return rc;
}

int connect(int fd, const struct sockaddr *addr, socklen_t size) {
    if (uv_thread_self() == Ziti_lib_thread()) {
        return connect_f(fd, addr, size);
    }

    in_port_t port = 0;
    in_addr_t in_addr = 0;
    if (addr->sa_family == AF_INET) {
        auto addr4 = (sockaddr_in *) addr;
        in_addr = addr4->sin_addr.s_addr;
        port = addr4->sin_port;
    } else if (addr->sa_family == AF_INET6) {
        auto addr6 = (const sockaddr_in6 *) addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
            in_addr = addr6->sin6_addr.s6_addr32[3];
            port = addr6->sin6_port;
        }
    }

    const char* hostname;
    if (in_addr == 0 || (hostname = Ziti_lookup(in_addr)) == nullptr) {
        return connect_f(fd, addr, size);
    }

    int flags = fcntl(fd, F_GETFL);
    int rc = Ziti_connect_addr(fd, hostname, (unsigned int)ntohs(port));
    fcntl(fd, F_SETFL, flags);
    return rc;
}

//int listen(int fd, int backlog) {
//    return Ziti_listen(fd, backlog);
//}
//
//int accept(int fd, struct sockaddr *addr, socklen_t *socklen) {
//    ziti_socket_t clt = Ziti_accept(fd, NULL, 0);
//    if (socklen)
//        *socklen = 0;
//    fprintf(stderr,"accepted client=%d\n", clt);
//    return clt;
//}

//int bind(int fd, const struct sockaddr *addr, socklen_t len) {
//    std::cerr << "in my bind(" << fd << ")" << std::endl;
//    int type = 0;
//    socklen_t l = sizeof(type);
//    ziti_context ztx = Ziti_load_context("/home/eugene/work/zeds/ek-zeds-host.json");
//    auto service ="super-service ek-test Z29vZ2xlLW9hdXRoMnwxMTM2MjIxOTc4NjgzNDE3NzY1MDg=";
//    int rc = Ziti_bind(fd, ztx, service, nullptr);
//    if (rc != 0) {
//        fprintf(stderr,"bind error(): %d/%s\n", Ziti_last_error(), ziti_errorstr(Ziti_last_error()));
//        if (Ziti_last_error() == EALREADY) {
//            return 0;
//        }
//    }
//    // int rc = getsockopt_f(fd, SOL_SOCKET, SO_DOMAIN, &type, &l);
////    fprintf(stderr,"\nfd = %d, type = %d, rc = %d\n", fd, type, rc);
////
////    if (type == AF_INET)
////        rc = bind_f(fd, addr, len);
////    else
////        rc = 0;
//    fprintf(stderr,"\nbind(): fd = %d, rc = %d\n", fd, rc);
//
//    return rc;
//}
