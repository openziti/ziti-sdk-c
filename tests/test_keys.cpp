/*
Copyright 2019 Netfoundry, Inc.

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

#include <catch2/catch.hpp>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#if _WIN32
#define PATH_MAX 256
#include <direct.h>
#include <processenv.h>

#define getcwd _getcwd
int setenv(const char* name, const char* value, int overwrite)
{
    return SetEnvironmentVariable(name, value);
}
#else
#include <unistd.h>
#endif
#include <cstring>
#include <nf/errors.h>
#include "../inc_internal/tls.h"

const char *pem = "pem:-----BEGIN EC PRIVATE KEY-----\n"
                  "MIGkAgEBBDCTcb9VYa4Hwi6Tw7UPTgYLIrvNL0ywtNHWt0rgHW08mEgZOg3V4AMW\n"
                  "eYvfvKoZS4agBwYFK4EEACKhZANiAARIxbNm7tYvdDmqeGVoMR1xZsEIJOY3y9av\n"
                  "6DmbquCPxFTpiKN01mhoLLdaOr4R1SFR9Y6sRsVCWPvbSX9zqAdRNg4b1gj3RZ4X\n"
                  "V9IwTC1BCcXCanQuR4Q3mceajgO8kYM=\n"
                  "-----END EC PRIVATE KEY-----";
const char *der = "der:MIGkAgEBBDCTcb9VYa4Hwi6Tw7UPTgYLIrvNL0ywtNHWt0rgHW08mEgZOg3V4AMWeYvfvKoZS4agBwYFK4EEACKhZANiA"
                  "ARIxbNm7tYvdDmqeGVoMR1xZsEIJOY3y9av6DmbquCPxFTpiKN01mhoLLdaOr4R1SFR9Y6sRsVCWPvbSX9zqAdRNg4b1g"
                  "j3RZ4XV9IwTC1BCcXCanQuR4Q3mceajgO8kYM=";


const char *derRSA = "der:MIIEpAIBAAKCAQEAxNE0PZkfHqBdajp0OGt1D7H3WAO7R6giLIvsBbIxAZTYccMGmo8HRq3MHABaTQNBXA/mmXOcbl1b"
                     "W9hCOa06ZdMM0mqtCqtM8tf/gKTF2LN88dh+rDtiEYKNzpS1X2FqcQI6iJStEtZuv3VW7NY9i5mEzUYysvVL6zHw3nBrps/ff"
                     "XsFnoqtVUobgJRVugLJeN0MUrO4hKcCwv+VwIX2vePAscCxsI3kJVbHP+zHHmcDforlwZjBPW/xLBOizMHM2v4GFtWvnFRYPZ"
                     "ajFvCoBYCNM68tACjnWqZ0GV0GVRe6II790+JZG0045E7mBKmXUYyb2QIPbeQvxYU/3EmHYwIDAQABAoIBACmeGy/TSxNM0bP+"
                     "vEiZ4Fz7QtQnpdhXIzLMO5JQxbAR61rS5HiWOfGmGnzpTi7uu0leS2KzYaassv7O0eIkUS7q29E6oXCaHGFVbz+il/tkqMzy/I"
                     "Yq4GfXdWjzZQ7QKJPQ5tOurJJJKY3un/zgqI72XXCSoXHaEL2hB8/hccIJ36enCXvittGC2rUPhTwzbEj7QEgglmrF3dl3vhvy"
                     "mOnaDi9PndBVlXgE2+0A67cZLeRrsS8rSJe0JiNGGbkJwG5y6O67cyexzyCNN0iFkQF3+BzqEsNQaEimG/ZcYjylJO1BPdH+9N"
                     "xw6/wwbGxeCeBYlt2ShQ/rjW0RkW6MRyECgYEA7Gbj/VeYIVNdCxgu03M9n8XecuhbciKTen/GUb3KcPxpFxuIaaPIFmzT5Hsh"
                     "MIVbDBa5wgOk3KaZEG6xQcalbSLelnquHOvw6AYCQaaUQZpsFiMDFFQ7U1fxd4+fgLJn+LWYCwqNDEoM3gm7w4KVBNce6HskLZX"
                     "shTST8I8dqCkCgYEA1SI3GV29VNe9U1sXeR5zIiea7p/wCiw0G3fqnXaLsr93ViyOtvaUQy4RY2GBWaLlFKyeTxnURXsUP5dcvq"
                     "lP0BGeW4STa8N4xy6Ffo6tlFw1poZOL2ehQTtNHpf+wgYCYAU2N6GaCoKY1UXb3thXVFPik3EzcBQH0uZheBZ/FKsCgYEA4BVfw"
                     "4NGd0B4D84qhNDV9x8ujylllTjlJtb7e/w1awg37Wlx0wEm5urdp9R3T3D5LupTxm6B1Y4txP/IEhtkL6E/8M/1PwD/aFBZzzVB"
                     "jzX7grhJcPmvCn9wKe8AOJPkLkKkDsM/lAiVTdtYGikrbF0ltSUU1AkrG9EM8pgWepECgYBvypWJ+ZAgW1STzzi9r8oGBS4PsdZ"
                     "PD6Z5Lenik9ZseF8Y1SA6OZXEsvot3WviXz23HV+f79VWaFtTi4n6+4XAhi1ApYZJxOqp1u3wVtgW9FKzuMhztvBu7bLitCjNDi"
                     "faw4EPpvTMRHnzi8Pq3CDaO3GhkoO/atI7vdksCui3JwKBgQCF33nv55RgY8BVTyGoaRzNrW4hebKyJBLFLMPdKeNtDx69rZQNC"
                     "Vje38arEoczZB5i7QicRpCYe27JJrQiK+kjkvkq8ca4v1mM+4UIuXEFuxuykt2IJPcspcJlD12u1k3A38cvtBS6ts7ZkzThCiyaj"
                     "xU3HFAf02w4AWRNr7JajQ==";

static int validate_key(mbedtls_pk_context *key) {
    unsigned char msg[256];
    for (int idx = 0; idx < sizeof(msg); msg[idx++] = (char) rand()) {}

    unsigned char sig[1024];
    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;
    size_t siglen;
    INFO("Signing");
    int rc = mbedtls_pk_sign(key, md_alg, msg, sizeof(msg), sig, &siglen,
                             (int (*)(void *, unsigned char *, size_t)) NULL, NULL);
    if (rc != 0) {
        return rc;
    }

    INFO("Verifying signature");
    rc = mbedtls_pk_verify(key, md_alg, msg, sizeof(msg), sig, siglen);

    return rc;
}

const char * softhsm_lib_path() {
    char * buffer = (char *)calloc(1, 1024);
    FILE * f = fopen("SOFTHSM2_LIB.txt", "rb");
    if (f) {
        if (fgets(buffer, 1024, f) != NULL) {
            fclose(f);
            buffer[strcspn(buffer, "\r\n")] = 0;
        }
    }
    if (buffer[0] == 0) {
        strcpy(buffer, "/usr/lib/softhsm/libsofthsm2.so");
    }

    printf("using pkcs11 module: %s\n", buffer);
    return buffer;
}

TEST_CASE("PEM format", "[keys][pem]") {

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    rc = load_key(&key, pem);
    REQUIRE(rc == ZITI_OK);

    REQUIRE(validate_key(&key) == 0);

    mbedtls_pk_free(&key);
}

TEST_CASE("DER format", "[keys][der]") {

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    rc = load_key(&key, der);
    REQUIRE(rc == ZITI_OK);

    REQUIRE(validate_key(&key) == 0);

    mbedtls_pk_free(&key);
}


TEST_CASE("DER format (RSA)", "[keys][der]") {

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    rc = load_key(&key, derRSA);
    REQUIRE(rc == ZITI_OK);

    REQUIRE(validate_key(&key) == 0);

    mbedtls_pk_free(&key);
}

TEST_CASE("FILE format", "[keys][file]") {

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    char spec[PATH_MAX + 256];

    sprintf(spec, "file://%s/test_key.pem", cwd);

    rc = load_key(&key, spec);
    INFO(ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);
    REQUIRE(validate_key(&key) == 0);

    mbedtls_pk_free(&key);
}

TEST_CASE("engine-PKCS11 format RSA key", "[keys][pkcs11][rsa]") {
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    char spec[1024];

    setenv("SOFTHSM2_CONF", "softhsm2.conf", 1);
    sprintf(spec, "pkcs11://%s?pin=2171&id=01", softhsm_lib_path());

    rc = load_key(&key, spec);
    INFO(ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);
    REQUIRE(validate_key(&key) == 0);

    mbedtls_pk_free(&key);
}

TEST_CASE("engine-PKCS11 format ECDSA key", "[keys][pkcs11][ecdsa]") {
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    char spec[1024];

    setenv("SOFTHSM2_CONF", "softhsm2.conf", 1);
    sprintf(spec, "pkcs11://%s?pin=2171&id=02", softhsm_lib_path());

    rc = load_key(&key, spec);
    INFO(ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);
    REQUIRE(validate_key(&key) == 0);

    mbedtls_pk_free(&key);
}

TEST_CASE("engine-PKCS11: invalid driver", "[keys][pkcs11]") {
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    char spec[1024];

    
    setenv("SOFTHSM2_CONF", "softhsm2.conf", 1);
    sprintf(spec, "pkcs11:///usr/lib/libnot-a-real-driver.so?pin=1111");

    rc = load_key(&key, spec);
    INFO(ziti_errorstr(rc));
    REQUIRE(rc == ZITI_KEY_INVALID);

    mbedtls_pk_free(&key);
}

TEST_CASE("engine-PKCS11: invalid pin", "[keys][pkcs11]") {
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    char spec[1024];

    setenv("SOFTHSM2_CONF", "softhsm2.conf", 1);
    sprintf(spec, "pkcs11://%s?pin=1111", softhsm_lib_path());

    rc = load_key(&key, spec);
    INFO(ziti_errorstr(rc));
    REQUIRE(rc == ZITI_KEY_INVALID);

    mbedtls_pk_free(&key);
}

TEST_CASE("engine-PKCS11: invalid slot", "[keys][pkcs11]") {
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = 0;

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    char spec[1024];

    setenv("SOFTHSM2_CONF", "softhsm2.conf", 1);
    sprintf(spec, "pkcs11://%s?slot=0x1234", softhsm_lib_path());

    rc = load_key(&key, spec);
    INFO(ziti_errorstr(rc));
    REQUIRE(rc == ZITI_KEY_INVALID);

    mbedtls_pk_free(&key);
}


