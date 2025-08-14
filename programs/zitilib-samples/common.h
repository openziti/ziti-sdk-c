// Copyright (c) 2025. NetFoundry Inc.
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

//
// Created by eugene on 8/6/25.
//

#ifndef ZITI_SDK_COMMON_H
#define ZITI_SDK_COMMON_H

#include <ziti/zitilib.h>

#include <stdint.h>

/**
 * Loads and completes authentication steps if necessary.
 *
 * @param identity
 * @return
 */
static inline ziti_handle_t init_context(const char *identity) {
    Ziti_lib_init();

    ziti_handle_t ztx;
    int rc = Ziti_load_context(&ztx, identity);
    if (ztx == ZITI_INVALID_CONFIG) {
        fprintf(stderr, "FATAL: failed to load ziti context from %s: %s\n", identity, ziti_errorstr(rc));
        exit(1);
    }

    // nothing else needed
    if (rc == ZITI_OK) return ztx;

    // identity requires external login
    if (rc == ZITI_EXTERNAL_LOGIN_REQUIRED) {
        ziti_jwt_signer_array signers = Ziti_get_ext_signers(ztx);
        if (signers == NULL) {
            fprintf(stderr, "FATAL: no external signers available for authentication\n");
            exit(1);
        }

        int i = 0;
        for (i = 0; signers[i] != NULL; i++) {
            const char *name = signers[i]->name;
            printf("%d: %s(%s)\n", i, name, signers[i]->provider_url);
        }

        int idx = -1;
        while (idx < 0 || idx >= i) {
            printf("\nSelect external signer by number[0-%d]: ", i - 1);
            if (fscanf(stdin, "%d", &idx) != 1) {
                printf("try again\n");
            }

        }

        printf("using external signer: %s\n", signers[idx]->name);

        char *url = Ziti_login_external(ztx, signers[idx]->name);

        printf("Use your browser to open this URL: %s\n", url);
        free(url);
        rc = Ziti_wait_for_auth(ztx, 60000); // wait for a minute
    }

    // identity requires MFA
    if (rc == ZITI_PARTIALLY_AUTHENTICATED) {
        char code[64] = {};
        printf("MFA required, enter TOTP code: ");
        size_t len = fread(code, sizeof(char), sizeof(code) - 1, stdin);
        if (len > 0 && code[len - 1] == '\n') {
            code[len - 1] = '\0'; // remove newline
        }

        rc = Ziti_login_totp(ztx, code);
    }

    if (rc == ZITI_OK) {
        fprintf(stderr, "FATAL: failed to complete authentication: %s\n", ziti_errorstr(rc));
        exit(1);
    }

    return ztx;
}

#endif //ZITI_SDK_COMMON_H
