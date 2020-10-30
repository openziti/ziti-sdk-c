/*
Copyright 2019-2020 NetFoundry, Inc.

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

#include "catch2/catch.hpp"
#include <string.h>

#if _WIN32
#include <windows.h>
#define timegm(v) _mkgmtime(v)
#define gmtime(v) _gmtime32(v)
#else
#define _GNU_SOURCE //add time.h include after defining _GNU_SOURCE
#include <time.h>
#endif

#include "internal_model.h"

using Catch::Matchers::Equals;

TEST_CASE("multi-edge-router session", "[model]") {

    const char *ns = "{\n"
                     "    \"_links\": {\n"
                     "      \"self\": {\n"
                     "        \"href\": \"./sessions/1276df75-3ba3-4658-98ad-fe5a0e96021a\"\n"
                     "      }\n"
                     "    },\n"
                     "    \"edgeRouters\": [\n"
                     "      {\n"
                     "        \"hostname\": \"ec2-18-223-205-231.us-east-2.compute.amazonaws.com\",\n"
                     "        \"name\": \"ziti-bridge-us-east\",\n"
                     "        \"urls\": {\n"
                     "          \"tls\": \"tls://ec2-18-223-205-231.us-east-2.compute.amazonaws.com:3022\"\n"
                     "        }\n"
                     "      },\n"
                     "      {\n"
                     "        \"hostname\": \"ec2-18-188-224-88.us-east-2.compute.amazonaws.com\","
                     "        \"name\": \"Test123\","
                     "        \"urls\": {"
                     "          \"tls\": \"tls://ec2-18-188-224-88.us-east-2.compute.amazonaws.com:3022\""
                     "        }"
                     "      }\n"
                     "    ],\n"
                     "    \"id\": \"1276df75-3ba3-4658-98ad-fe5a0e96021a\",\n"
                     "    \"token\": \"caaf0f67-5394-4ddd-b718-bfdc8fcfb367\"\n"
                     "}";

    ziti_net_session *s;
    int rc = parse_ziti_net_session_ptr(&s, ns, (int) strlen(ns));

    dump_ziti_net_session(s, 0);

    REQUIRE(s->edge_routers[0] != nullptr);
    REQUIRE(s->edge_routers[1] != nullptr);
    REQUIRE(s->edge_routers[2] == nullptr);

    REQUIRE(strcmp(s->edge_routers[1]->ingress.tls, "tls://ec2-18-188-224-88.us-east-2.compute.amazonaws.com:3022") ==
            0);

    free_ziti_net_session(s);
    free(s);
}

TEST_CASE("parse-services-array", "[model]") {
    const char *json = "[\n"
                     " {\n"
                       "    \"id\": \"4aba8ab0-df3f-45fd-bed7-79127d2c3d29\",\n"
                       "    \"createdAt\": \"2020-01-10T17:04:30.679489183Z\",\n"
                       "    \"updatedAt\": \"2020-01-10T17:04:30.679489183Z\",\n"
                       "    \"_links\": {\n"
                       "      \"edge-routers\": {\n"
                       "        \"href\": \"./services/4aba8ab0-df3f-45fd-bed7-79127d2c3d29/edge-routers\"\n"
                       "      },\n"
                       "      \"self\": {\n"
                       "        \"href\": \"./services/4aba8ab0-df3f-45fd-bed7-79127d2c3d29\"\n"
                       "      },\n"
                       "      \"service-policies\": {\n"
                       "        \"href\": \"./services/4aba8ab0-df3f-45fd-bed7-79127d2c3d29/identities\"\n"
                       "      }\n"
                       "    },\n"
                       "    \"tags\": {},\n"
                       "    \"name\": \"hosting\",\n"
                       "    \"dns\": {\n"
                       "      \"hostname\": \"sample.host.org\",\n"
                       "      \"port\": 80\n"
                       "    },\n"
                       "    \"endpointAddress\": \"tcp:httpbin.org:80\",\n"
                       "    \"egressRouter\": \"1bcefeb5-6385-42e4-bd92-be1085825b58\",\n"
                       "    \"edgeRouterRoles\": null,\n"
                       "    \"roleAttributes\": null,\n"
                       "    \"permissions\": [\n"
                       "      \"Bind\"\n"
                       "    ]\n"
                       "  },"
                     " {\n"
                       "    \"id\": \"4aba8ab0-df3f-45fd-bed7-79127d2c3d29\",\n"
                       "    \"createdAt\": \"2020-01-10T17:04:30.679489183Z\",\n"
                       "    \"updatedAt\": \"2020-01-10T17:04:30.679489183Z\",\n"
                       "    \"_links\": {\n"
                       "      \"edge-routers\": {\n"
                       "        \"href\": \"./services/4aba8ab0-df3f-45fd-bed7-79127d2c3d29/edge-routers\"\n"
                       "      },\n"
                       "      \"self\": {\n"
                       "        \"href\": \"./services/4aba8ab0-df3f-45fd-bed7-79127d2c3d29\"\n"
                       "      },\n"
                       "      \"service-policies\": {\n"
                       "        \"href\": \"./services/4aba8ab0-df3f-45fd-bed7-79127d2c3d29/identities\"\n"
                       "      }\n"
                       "    },\n"
                       "    \"tags\": {},\n"
                       "    \"name\": \"httpbin\",\n"
                       "    \"endpointAddress\": \"tcp:httpbin.org:80\",\n"
                       "    \"egressRouter\": \"1bcefeb5-6385-42e4-bd92-be1085825b58\",\n"
                       "    \"edgeRouterRoles\": null,\n"
                       "    \"roleAttributes\": null,\n"
                       "    \"permissions\": [\n"
                       "      \"Dial\"\n"
                       "    ]\n"
                       "  }"
                       "]";

    ziti_service **services;
    int rc = parse_ziti_service_array(&services, json, (int) strlen(json));
    REQUIRE(rc == 0);
    ziti_service **s;
    int idx;

    for (idx = 0, s = services; *s != nullptr; s++, idx++) {
        printf("service #%d: %s\n", idx, (*s)->name);
        dump_ziti_service(services[idx], 2);
    }
    REQUIRE(idx == 2);
    REQUIRE(services[idx] == nullptr);

    REQUIRE_THAT(services[0]->name, Equals("hosting"));
    REQUIRE_THAT(services[0]->permissions[0], Equals("Bind"));

    REQUIRE(strcmp(services[1]->name, "httpbin") == 0);
    REQUIRE_THAT(services[1]->permissions[0], Equals("Dial"));

    free_ziti_service_array(&services);
}

TEST_CASE("parse-session", "[model]") {

    const char *json = "{\n"
                       "        \"_links\": {\n"
                       "            \"self\": {\n"
                       "                \"href\": \"./current-session\"\n"
                       "            }\n"
                       "        },\n"
                       "        \"createdAt\": \"2019-10-14T14:49:48.340512Z\",\n"
                       "        \"expiresAt\": \"2019-10-14T14:59:48.340512Z\",\n"
                       "        \"id\": \"f0bd2587-1510-455a-96ca-6f1aea1c04f3\",\n"
                       "        \"identity\": {\n"
                       "            \"_links\": {\n"
                       "                \"self\": {\n"
                       "                    \"href\": \"./identities/da71c941-576b-4b2a-9af2-53867c6d1ec5\"\n"
                       "                }\n"
                       "            },\n"
                       "            \"entity\": \"\",\n"
                       "            \"id\": \"da71c941-576b-4b2a-9af2-53867c6d1ec5\",\n"
                       "            \"name\": \"Default Admin\"\n"
                       "        },\n"
                       "        \"tags\": {},\n"
                       "        \"token\": \"6fb97fe8-3507-4811-a83a-1d660b1022a3\",\n"
                       "        \"updatedAt\": \"2019-10-14T14:49:48.340512Z\"\n"
                       "    }";

    ziti_session *session;
    int rc = parse_ziti_session_ptr(&session, json, (int) strlen(json));
    REQUIRE(rc == 0);

    REQUIRE_THAT(session->id, Equals("f0bd2587-1510-455a-96ca-6f1aea1c04f3"));
    REQUIRE_THAT(session->token, Equals("6fb97fe8-3507-4811-a83a-1d660b1022a3"));
    struct tm *expiry = gmtime(&session->expires->tv_sec);
    REQUIRE(expiry->tm_year == 2019 - 1900);
    REQUIRE(expiry->tm_mon == 10 - 1);
    REQUIRE(expiry->tm_mday == 14);
    REQUIRE(expiry->tm_hour == 14);
    REQUIRE(expiry->tm_min == 59);
    REQUIRE(expiry->tm_sec == 48);

    REQUIRE_THAT(session->identity->name, Equals("Default Admin"));

    free_ziti_session(session);
    free(session);
}

TEST_CASE("parse-error", "[model]") {
    const char *json = "{\n"
                       "        \"args\": {\n"
                       "            \"urlVars\": {}\n"
                       "        }, \n"
                       "        \"cause\": null, \n"
                       "        \"causeMessage\": \"\", \n"
                       "        \"code\": \"UNAUTHORIZED\", \n"
                       "        \"message\": \"The request could not be completed. The session is not authorized or the credentials are invalid\", \n"
                       "        \"requestId\": \"e6123851-2e6d-43cb-8bd5-0d363dd66636\"\n"
                       "    }";

    ziti_error err;
    int rc = parse_ziti_error(&err, json, (int) strlen(json));
    REQUIRE(rc == 0);
    REQUIRE_THAT(err.code, Equals("UNAUTHORIZED"));
    free_ziti_error(&err);
}

TEST_CASE("parse-enrollment-jwt", "[model]") {
    const char *json = "{\n"
                       "\"em\":\"ott\",\n"
                       "\"exp\":1573411752,\n"
                       "\"iss\":\"https://demo.ziti.netfoundry.io:1080\",\n"
                       "\"jti\":\"f581d770-fffc-11e9-a81a-000d3a1b4b17\",\n"
                       "\"sub\":\"c17291f4-37fe-4cdb-9f57-3eb757b648f5\"\n"
                       "}";

    ziti_enrollment_jwt ej;
    int rc = parse_ziti_enrollment_jwt(&ej, json, (int) strlen(json));
    REQUIRE_THAT(ej.method, Equals("ott"));
    REQUIRE_THAT(ej.controller, Equals("https://demo.ziti.netfoundry.io:1080"));
    REQUIRE_THAT(ej.subject, Equals("c17291f4-37fe-4cdb-9f57-3eb757b648f5"));
    REQUIRE_THAT(ej.token, Equals("f581d770-fffc-11e9-a81a-000d3a1b4b17"));
    free_ziti_enrollment_jwt(&ej);
}

TEST_CASE("test service array", "[model]") {
    const char *json = R"([
  {
    "id": "724b06a4-0ebb-4954-b62b-7525bf743a0d",
    "createdAt": "2020-04-01T20:11:53.609058348Z",
    "updatedAt": "2020-04-01T20:11:53.609058348Z",
    "_links": {
      "configs": {
        "href": "./services/724b06a4-0ebb-4954-b62b-7525bf743a0d/configs"
      },
      "self": {
        "href": "./services/724b06a4-0ebb-4954-b62b-7525bf743a0d"
      },
      "service-edge-router-policies": {
        "href": "./services/724b06a4-0ebb-4954-b62b-7525bf743a0d/service-edge-router-policies"
      },
      "service-policies": {
        "href": "./services/724b06a4-0ebb-4954-b62b-7525bf743a0d/service-policies"
      },
      "terminators": {
        "href": "./services/724b06a4-0ebb-4954-b62b-7525bf743a0d/terminators"
      }
    },
    "tags": {},
    "name": "httpbin",
    "terminatorStrategy": "",
    "roleAttributes": null,
    "permissions": [
      "Dial"
    ],
    "configs": null,
    "config": {}
  }
])";

    ziti_service_array arr;
    REQUIRE(parse_ziti_service_array(&arr, json, strlen(json)) == 0);
    REQUIRE(arr != nullptr);
    CHECK(arr[1] == nullptr);
    CHECK_THAT(arr[0]->name, Equals("httpbin"));

    free_ziti_service_array(&arr);
}


TEST_CASE("service config test", "[model]") {
    const char *j = R"({
    "_links": {
      "configs": {
        "href": "./services/c8c07cb8-5234-4106-92ea-fde5721095fd/configs"
      },
      "self": {
        "href": "./services/c8c07cb8-5234-4106-92ea-fde5721095fd"
      },
      "service-edge-router-policies": {
        "href": "./services/c8c07cb8-5234-4106-92ea-fde5721095fd/service-edge-router-policies"
      },
      "service-policies": {
        "href": "./services/c8c07cb8-5234-4106-92ea-fde5721095fd/service-policies"
      },
      "terminators": {
        "href": "./services/c8c07cb8-5234-4106-92ea-fde5721095fd/terminators"
      }
    },
    "createdAt": "2020-04-28T17:43:52.717Z",
    "id": "c8c07cb8-5234-4106-92ea-fde5721095fd",
    "tags": {},
    "updatedAt": "2020-05-12T02:56:36.860Z",
    "config": {
      "ziti-tunneler-client.v1": {
        "hostname": "hello.ziti",
        "port": 80
      },
      "intercept.v1": {
        "protocols": [ "tcp", "udp" ],
        "addresses": [ "1.2.3.4" ],
        "portRanges": [ { "low": 80, "high": 80 }, { "low": 443, "high": 443 } ],
        "dialOptions": { "identity": "helloitsme" }
      }
    },
    "configs": [
      "d1339ad5-6556-4297-b357-308b3bc79db0",
      "tUussYpGR"
    ],
    "name": "hello-svc",
    "permissions": [
      "Bind",
      "Dial"
    ],
    "roleAttributes": null,
    "terminatorStrategy": "smartrouting"
  }
)";

    ziti_service s;
    REQUIRE(parse_ziti_service(&s, j, strlen(j)) == 0);

    {
        ziti_client_cfg_v1 cfg;
        REQUIRE(ziti_service_get_config(&s, "ziti-tunneler-client.v1", &cfg,
                                        (int (*)(void *, const char *, size_t)) (parse_ziti_client_cfg_v1)) == 0);

        CHECK_THAT(cfg.hostname, Equals("hello.ziti"));
        CHECK(cfg.port == 80);
        free_ziti_client_cfg_v1(&cfg);
    }

    {
        ziti_intercept_cfg_v1 cfg;
        REQUIRE(ziti_service_get_config(&s, "intercept.v1", &cfg,
                                        (int (*)(void *, const char *, size_t)) (parse_ziti_intercept_cfg_v1)) == 0);

        CHECK_THAT(cfg.protocols[0], Equals("tcp"));
        CHECK_THAT(cfg.addresses[0], Equals("1.2.3.4"));
        CHECK(cfg.port_ranges[0]->high == 80);
        free_ziti_intercept_cfg_v1(&cfg);
    }

    free_ziti_service(&s);
}

TEST_CASE("config change", "[model]") {
    const char *j1 = R"({
    "id": "c8c07cb8-5234-4106-92ea-fde5721095fd",
    "tags": {},
    "config": {
      "ziti-tunneler-client.v1": {
        "hostname": "hello.ziti",
        "port": 80
      }
    },
    "configs": [
      "d1339ad5-6556-4297-b357-308b3bc79db0"
    ],
    "name": "hello-svc",
    "permissions": [
      "Bind",
      "Dial"
    ],
    "roleAttributes": null,
    "terminatorStrategy": "smartrouting"
  }
)";

    const char *j2 = R"({
    "id": "c8c07cb8-5234-4106-92ea-fde5721095fd",
    "tags": {},
    "config": {
      "ziti-tunneler-client.v1": {
        "hostname": "hello.ziti",
        "port": 8080
      }
    },
    "configs": [
      "d1339ad5-6556-4297-b357-308b3bc79db0"
    ],
    "name": "hello-svc",
    "permissions": [
      "Bind",
      "Dial"
    ],
    "roleAttributes": null,
    "terminatorStrategy": "smartrouting"
  }
)";


    ziti_service s, s1, s2;
    REQUIRE(parse_ziti_service(&s, j1, strlen(j1)) == 0);
    REQUIRE(parse_ziti_service(&s1, j1, strlen(j1)) == 0);
    REQUIRE(parse_ziti_service(&s2, j2, strlen(j2)) == 0);

    CHECK(cmp_ziti_service(&s, &s1) == 0);
    CHECK(cmp_ziti_service(&s, &s2) != 0);
    CHECK(cmp_ziti_service(&s2, &s1) != 0);


    free_ziti_service(&s);
    free_ziti_service(&s1);
    free_ziti_service(&s2);
}

TEST_CASE("identity tags", "[model]") {
    const char *json = R"(        {
            "_links": {
                "edge-router-policies": {
                    "href": "./identities/499af8c0-bede-4305-b4fb-334e2750e872/edge-routers"
                },
                "self": {
                    "href": "./identities/499af8c0-bede-4305-b4fb-334e2750e872"
                }
            },
            "createdAt": "2020-03-06T20:52:14.790Z",
            "id": "499af8c0-bede-4305-b4fb-334e2750e872",
            "tags": {
                "type": "test phone",
                "active": true,
                "answer": 42,
                "owner": "Eugene"
            },
            "updatedAt": "2020-07-30T16:50:59.461Z",
            "authenticators": {
                "cert": {
                    "fingerprint": "ae4b6a14167c816f14fc0434f55213c2b5c9df91"
                }
            },
            "enrollment": {},
            "envInfo": {
                "arch": "x86_64",
                "os": "Linux",
                "osRelease": "5.4.0-42-generic",
                "osVersion": "#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020"
            },
            "isAdmin": false,
            "isDefaultAdmin": false,
            "name": "ek-hermes",
            "roleAttributes": [
                "#ek",
                "ek"
            ],
            "sdkInfo": {
                "branch": "model-tags-support",
                "revision": "fa9a8a6",
                "type": "ziti-sdk-c",
                "version": "0.15.2.7-local"
            },
            "type": {
                "_links": {
                    "self": {
                        "href": "./identities/5b53fb49-51b1-4a87-a4e4-edda9716a970"
                    }
                },
                "entity": "identities",
                "id": "5b53fb49-51b1-4a87-a4e4-edda9716a970",
                "name": "Device"
            },
            "typeId": "5b53fb49-51b1-4a87-a4e4-edda9716a970"
        }
)";

    ziti_identity id;
    REQUIRE(parse_ziti_identity(&id, json, strlen(json)) == 0);

    tag *t = (tag *) model_map_get(&id.tags, "owner");
    REQUIRE(t != nullptr);
    REQUIRE(t->type == tag_string);
    REQUIRE_THAT(t->string_value, Equals("Eugene"));

    t = (tag *) model_map_get(&id.tags, "active");
    REQUIRE(t != nullptr);
    REQUIRE(t->type == tag_bool);
    REQUIRE(t->bool_value == true);

    t = (tag *) model_map_get(&id.tags, "answer");
    REQUIRE(t != nullptr);
    REQUIRE(t->type == tag_number);
    REQUIRE(t->num_value == 42);

    char buf[1024];
    size_t l;
    json_from_ziti_identity(&id, buf, 1024, &l);

    printf("%.*s", (int)l, buf);

    free_ziti_identity(&id);
}