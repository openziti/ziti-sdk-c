![Ziggy using the ziti-sdk-c](https://raw.githubusercontent.com/openziti/branding/main/images/banners/C.jpg)

# OpenZiti C SDK

![Build Status](https://github.com/openziti/ziti-sdk-c/actions/workflows/cmake.yml/badge.svg?branch=main)

The OpenZiti C SDK allows developers to create their own custom OpenZiti network endpoint applications.

OpenZiti is a modern, programmable network overlay with associated edge components, for application-embedded,
zero trust network connectivity, written by developers for developers.
The SDK harnesses that power via APIs that allow developers to imagine and develop solutions beyond what
OpenZiti handles by default.

This SDK does the following:

- enable network endpoint clients allow a device to [dial (access)](#dialing-a-service)
  or [bind (host)](#binding-to-a-service) OpenZiti Services
- provides [authentication](https://openziti.io/docs/learn/core-concepts/security/authentication/auth) interfaces for
  [x509 certificates](#example-code-configuration) flows
- collects and submits security posture collection/submission
  for [Posture Checks](https://openziti.io/docs/learn/core-concepts/security/authorization/posture-checks)
- allows applications to bind or dial services via standard [`socket`](#high-level-zitilib-api) interfaces

## Configuring Your Application to use OpenZiti C SDK

The easiest way to embed Ziti SDK in your app is to pull the project into your CMake build

```cmake
FetchContent_Declare(ziti-sdk-c
        GIT_REPOSITORY https://github.com/openziti/ziti-sdk-c.git
        GIT_TAG ${LATEST_ZITI_RELEASE}
        )
FetchContent_MakeAvailable(ziti-sdk-c)

# ...
# ...

add_executable(most-secure-app-ever ${my_sources})
target_link_libraries(most-secure-app-ever PRIVATE ziti)

```

You will also need other libraries that OpenZiti SDK uses (they are specified in [vcpkg.json](vcpkg.json)):

| library     | usage                          |
|-------------|--------------------------------|
| `libuv`     | event loop                     |
| `openssl`   | TLS                            |
| `zlib`      | HTTPS compression              |
| `llhttp`    | HTTP parsing                   |
| `libsodium` | OpenZiti end-to-end encryption |

There are multiple ways to get those 3rd party dependencies into your build: system level, CMake `FetchContent`, vcpkg,
etc.
We recommend using [`vcpkg`](https://vcpkg.io/).

If you want to contribute/build/hack this SDK in standalone mode
see the [BUILD.md](BUILD.md) for information on how to do it.

## Using OpenZiti in Your Application

### High-Level (`Zitilib`) API

The high-level API was developed to simplify embedding OpenZiti in an application.
The main feature of this API is presenting Ziti connections as regular socket file descriptors (or handles on Windows).
These sockets can be used both blocking and non-blocking modes.

#### SDK Initialization and Teardown

There are just three functions that cover SDK initialization and teardown. 
Additional steps may be required to complete authentication. See example below.

| function              | purpose                                                                                                                    |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------|
| `Ziti_lib_init()`     | initializes Ziti SDK background event loop that runs all internal SDK tasks                                                |
| `Ziti_load_context()` | loads an enrolled [ziti identity](https://openziti.io/docs/learn/core-concepts/identities/overview) from the provided file |
| `Ziti_lib_shutdown()` | gracefully shuts down all loaded identities and terminates the event loop                                                  |

```c
#include <ziti/zitilib.h>

int main(int argc, char *argv[]) {

    const char *identity_file = process_args(argc, argv);

    Ziti_lib_init();
    
    ziti_handle_t ztx = NULL;
    int err = Ziti_load_context(&ztx, identity_file);
    
    // simplest case, identity is loaded successfully with key/certificate
    if (err == ZITI_OK) goto important_work;
    
    // identity does not have key/certificate or requires secondary auth with external provider
    if (err == ZITI_EXTERNAL_LOGIN_REQUIRED) {
        // optional step: query supported external login providers
        ziti_jwt_signer_array signers = Ziti_get_ext_signers(ztx);

        // select
        const char *singer = ...; // prompt user or use a known provider
        
        char *url = Ziti_login_external(ztx, signer);
        // prompt user to open URL in browser

        // wait for external login to complete
        err = Ziti_wait_for_auth(ztx, 60000); // wait for a minute
    }
    
    // identity requires TOTP code for secondary authentication
    if (err == ZITI_PARTIALLY_AUTHENTICATED) {
        char *code = ...; // prompt user for TOTP code
        err = Ziti_login_totp(ztx, code);
    }
    
    if (err != ZITI_OK) {
        fprintf(stderr, "Failed to load identity: %s\n", Ziti_strerror(rc));
        // handle error, e.g. exit
    }
    
important_work:
    ...
    


    Ziti_lib_shutdown();
}
```

Once `ziti_context` is loaded it can be used to dial a service or bind to a service (provided the identity has proper
access to it).

#### Dialing a service

| function                                       | usage                                                              |
|------------------------------------------------|--------------------------------------------------------------------|
| `Ziti_connect(sock, ztx, service, terminator)` | connects given socket to the service/terminator within the context |
| `Ziti_connect_addr(sock, hostname, port)`      | connects given socket to the specified intercept address           |

```c
      ziti_socket_t sock = Ziti_socket(SOCK_STREAM);
      int error = Ziti_connect(sock, ztx, "my-secure-service", NULL);

      // use sock as normal socket
      do {
          write(sock, ...);
          read(sock, ...);

      } while (!done);

      close(sock);

```

#### Binding to a service

| function                                   | usage                                                                       |
|--------------------------------------------|-----------------------------------------------------------------------------|
| `Ziti_bind(srv, ztx, service, terminator)` | binds given socket to the service/terminator within the context             |
| `Ziti_listen(sock, backlog)`               | sets maximum number of pending inbound connections (similar to TCP backlog) |
| `Ziti_accept(srv, caller, caller_len)`     | accepts incoming connection and returns peer socket/handle                  |

```c
      ziti_socket_t srv = Ziti_socket(SOCK_STREAM);
      int error = Ziti_bind(srv, ztx, "my-secure-service", NULL);
      Ziti_listen(srv, 10); // sets accept backlog

      do {
          char caller[128];
          ziti_socket_t clt = Ziti_accept(srv, caller, (int)sizeof(caller));

          // use client as normal socket
          process_client(clt);

      } while (!done);

      close(srv);
```

## Getting Help

------------
Please use these community resources for getting help. We use GitHub [issues](https://github.com/openziti/ziti-sdk-c/issues)
for tracking bugs and feature requests and have limited bandwidth to address them.

- Read [the docs](https://docs.openziti.io/)
- Ask a question on [Discourse](https://openziti.discourse.group/)

Copyright&copy; NetFoundry Inc.
