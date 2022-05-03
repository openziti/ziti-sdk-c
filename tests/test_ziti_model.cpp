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
#include <string>
#include <uv.h>

#if _WIN32
#include <windows.h>
#define timegm(v) _mkgmtime(v)
#define gmtime(v) _gmtime32(v)
#else
#   ifndef _GNU_SOURCE
#      define _GNU_SOURCE //add time.h include after defining _GNU_SOURCE
#   endif

#include <ctime>
#include <arpa/inet.h>

#endif

#include "internal_model.h"

using Catch::Matchers::Equals;

TEST_CASE("posture response response", "[model]") {
    const char *json = R"({"services":[{"id":".T9TTXjPYy","name":"net-cat2","postureQueryType":"MFA","timeout":600,"timeoutRemaining":300}]})";

    ziti_pr_response pr_resp;
    int rc = parse_ziti_pr_response(&pr_resp, json, (int) strlen(json));
    REQUIRE(rc > 0);


    int idx;

    for (idx = 0; pr_resp.services[idx] != nullptr; idx++) {

    }
    REQUIRE(idx == 1);


    REQUIRE_THAT(pr_resp.services[0]->id, Equals(".T9TTXjPYy"));
    REQUIRE_THAT(pr_resp.services[0]->name, Equals("net-cat2"));
    REQUIRE_THAT(pr_resp.services[0]->posture_query_type, Equals("MFA"));
    REQUIRE(*pr_resp.services[0]->timeout == 600);
    REQUIRE(*pr_resp.services[0]->timeoutRemaining == 300);

    free_ziti_pr_response(&pr_resp);
}

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

    REQUIRE(s->edge_routers[0] != nullptr);
    REQUIRE(s->edge_routers[1] != nullptr);
    REQUIRE(s->edge_routers[2] == nullptr);

    const char *tls = (const char*)model_map_get(&s->edge_routers[1]->ingress, "tls");
    REQUIRE_THAT(tls, Catch::Matches("tls://ec2-18-188-224-88.us-east-2.compute.amazonaws.com:3022"));

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
                     "   {\n"
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
                       "    ],\n"
                       "    \"postureQueries\": null\n"
                       "  },"
                       "  {\n"
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
                       "    ],\n"
                       "    \"postureQueries\": [\n"
                       "        {\n"
                       "            \"isPassing\": false,\n"
                       "            \"policyId\": \"FqPD7ohMR\",\n"
                       "            \"postureQueries\": [\n"
                       "                {\n"
                       "                    \"_links\": {\n"
                       "                        \"self\": {\n"
                       "                            \"href\": \"./posture-checks/OjUDnohGg\"\n"
                       "                        }\n"
                       "                    },\n"
                       "                    \"createdAt\": \"2020-11-05T14:30:18.794Z\",\n"
                       "                    \"id\": \"OjUDnohGg\",\n"
                       "                    \"tags\": {},\n"
                       "                    \"updatedAt\": \"2020-11-05T14:30:18.794Z\",\n"
                       "                    \"isPassing\": false,\n"
                       "                    \"queryType\": \"OS\"\n"
                       "                },\n"
                       "                {\n"
                       "                    \"_links\": {\n"
                       "                        \"self\": {\n"
                       "                            \"href\": \"./posture-checks/j08v7T2MR\"\n"
                       "                        }\n"
                       "                    },\n"
                       "                    \"createdAt\": \"2020-11-05T14:30:18.397Z\",\n"
                       "                    \"id\": \"j08v7T2MR\",\n"
                       "                    \"tags\": {},\n"
                       "                    \"updatedAt\": \"2020-11-05T14:30:18.397Z\",\n"
                       "                    \"isPassing\": false,\n"
                       "                    \"process\": {\n"
                       "                        \"osType\": \"Windows\",\n"
                       "                        \"path\": \"C:\\\\Users\\\\andrew\\\\go\\\\bin\\\\test.exe\"\n"
                       "                    },\n"
                       "                    \"queryType\": \"PROCESS\"\n"
                       "                },\n"
                       "                {\n"
                       "                    \"_links\": {\n"
                       "                        \"self\": {\n"
                       "                            \"href\": \"./posture-checks/vG8v7ThGg\"\n"
                       "                        }\n"
                       "                    },\n"
                       "                    \"createdAt\": \"2020-11-05T14:30:17.993Z\",\n"
                       "                    \"id\": \"vG8v7ThGg\",\n"
                       "                    \"tags\": {},\n"
                       "                    \"updatedAt\": \"2020-11-05T14:30:17.993Z\",\n"
                       "                    \"isPassing\": true,\n"
                       "                    \"queryType\": \"DOMAIN\"\n"
                       "                },\n"
                       "                {\n"
                       "                    \"_links\": {\n"
                       "                        \"self\": {\n"
                       "                            \"href\": \"./posture-checks/wyyDnThMR\"\n"
                       "                        }\n"
                       "                    },\n"
                       "                    \"createdAt\": \"2020-11-05T14:30:17.593Z\",\n"
                       "                    \"id\": \"wyyDnThMR\",\n"
                       "                    \"tags\": {},\n"
                       "                    \"updatedAt\": \"2020-11-05T14:30:17.593Z\",\n"
                       "                    \"isPassing\": false,\n"
                       "                    \"queryType\": \"MAC\"\n"
                       "                }\n"
                       "            ]\n"
                       "        }\n"
                       "    ]\n"
                       "  }"
                       "]";

    ziti_service **services;
    int rc = parse_ziti_service_array(&services, json, (int) strlen(json));
    REQUIRE(rc == strlen(json));
    ziti_service **s;
    int idx;

    for (idx = 0, s = services; *s != nullptr; s++, idx++) {
        printf("service #%d: %s\n", idx, (*s)->name);
    }
    REQUIRE(idx == 3);
    REQUIRE(services[idx] == nullptr);

    REQUIRE_THAT(services[0]->name, Equals("hosting"));
    REQUIRE(*services[0]->permissions[0] == ziti_session_types.Bind);
    REQUIRE(services[0]->posture_query_set == nullptr); //missing

    REQUIRE(strcmp(services[1]->name, "httpbin") == 0);
    REQUIRE(*services[1]->permissions[0] == ziti_session_types.Dial);

    REQUIRE(services[1]->posture_query_set == nullptr); //present but null

    REQUIRE(services[2]->posture_query_set != nullptr); //present

    ziti_posture_query_set_array query_set;
    for (idx = 0, query_set = services[2]->posture_query_set; *query_set != nullptr; query_set++, idx++) {}
    REQUIRE(idx == 1);

    REQUIRE_THAT(services[2]->posture_query_set[0]->policy_id, Equals("FqPD7ohMR"));
    REQUIRE(!services[2]->posture_query_set[0]->is_passing);
    REQUIRE(services[2]->posture_query_set[0]->posture_queries != nullptr);

    ziti_posture_query_array pq_arr = nullptr;
    for (idx = 0, pq_arr = services[2]->posture_query_set[0]->posture_queries; *pq_arr != nullptr; pq_arr++, idx++) {}
    REQUIRE(idx == 4);

    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[0]->id, Equals("OjUDnohGg"));
    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[0]->query_type, Equals("OS"));
    REQUIRE(!services[2]->posture_query_set[0]->posture_queries[0]->is_passing);
    REQUIRE(services[2]->posture_query_set[0]->posture_queries[0]->process == nullptr);


    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[1]->id, Equals("j08v7T2MR"));
    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[1]->query_type, Equals("PROCESS"));
    REQUIRE(!services[2]->posture_query_set[0]->posture_queries[1]->is_passing);
    REQUIRE(services[2]->posture_query_set[0]->posture_queries[1]->process != nullptr);
    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[1]->process->path, Equals("C:\\Users\\andrew\\go\\bin\\test.exe"));

    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[2]->id, Equals("vG8v7ThGg"));
    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[2]->query_type, Equals("DOMAIN"));
    REQUIRE(services[2]->posture_query_set[0]->posture_queries[2]->is_passing);
    REQUIRE(services[2]->posture_query_set[0]->posture_queries[2]->process == nullptr);

    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[3]->id, Equals("wyyDnThMR"));
    REQUIRE_THAT(services[2]->posture_query_set[0]->posture_queries[3]->query_type, Equals("MAC"));
    REQUIRE(!services[2]->posture_query_set[0]->posture_queries[3]->is_passing);
    REQUIRE(services[2]->posture_query_set[0]->posture_queries[3]->process == nullptr);

    free_ziti_service_array(&services);
}

TEST_CASE("parse-api-session", "[model]") {

    const char *json = "{\n"
                       "        \"_links\": {\n"
                       "            \"self\": {\n"
                       "                \"href\": \"./current-api-session\"\n"
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

    ziti_api_session *session;
    int rc = parse_ziti_api_session_ptr(&session, json, (int) strlen(json));
    REQUIRE(rc > 0);

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

    free_ziti_api_session(session);
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
    REQUIRE(rc > 0);
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
    REQUIRE(parse_ziti_service_array(&arr, json, strlen(json)) == strlen(json));
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
    REQUIRE(parse_ziti_service(&s, j, strlen(j)) > 0);

    {
        ziti_client_cfg_v1 cfg;
        REQUIRE(ziti_service_get_config(&s, "ziti-tunneler-client.v1", &cfg,
                                        (int (*)(void *, const char *, size_t)) (parse_ziti_client_cfg_v1)) == 0);

        CHECK(cfg.hostname.type == ziti_address_hostname);
        CHECK_THAT(cfg.hostname.addr.hostname, Equals("hello.ziti"));
        CHECK(cfg.port == 80);

        ziti_intercept_cfg_v1 intercept;
        ziti_intercept_from_client_cfg(&intercept, &cfg);
        CHECK_THAT(intercept.protocols[0], Equals("tcp"));
        CHECK_THAT(intercept.protocols[1], Equals("udp"));
        CHECK(intercept.protocols[2] == nullptr);

        CHECK(intercept.port_ranges[0]->high == 80);
        CHECK(intercept.port_ranges[0]->low == 80);
        CHECK(intercept.port_ranges[1] == nullptr);

        CHECK(intercept.addresses[0]->type == ziti_address_hostname);
        CHECK_THAT(intercept.addresses[0]->addr.hostname, Equals("hello.ziti"));
        CHECK(intercept.addresses[1] == nullptr);

        free_ziti_client_cfg_v1(&cfg);
        free_ziti_intercept_cfg_v1(&intercept);
    }

    {
        ziti_intercept_cfg_v1 cfg;
        REQUIRE(ziti_service_get_config(&s, "intercept.v1", &cfg,
                                        (int (*)(void *, const char *, size_t)) (parse_ziti_intercept_cfg_v1)) == 0);

        CHECK_THAT(cfg.protocols[0], Equals("tcp"));
        // TODO CHECK_THAT(cfg.addresses[0], Equals("1.2.3.4"));
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
    REQUIRE(parse_ziti_service(&s, j1, strlen(j1)) > 0);
    REQUIRE(parse_ziti_service(&s1, j1, strlen(j1)) > 0);
    REQUIRE(parse_ziti_service(&s2, j2, strlen(j2)) > 0);

    CHECK(cmp_ziti_service(&s, &s1) == 0);
    CHECK(cmp_ziti_service(&s, &s2) != 0);
    CHECK(cmp_ziti_service(&s2, &s1) != 0);


    free_ziti_service(&s);
    free_ziti_service(&s1);
    free_ziti_service(&s2);
}

TEST_CASE("parse-ctrl-version", "[model]") {
    const char *json = R"( {
        "apiVersions": {
            "edge": {
                "v1": {
                    "path": "/edge/v1"
                }
            }
        },
        "buildDate": "2021-04-23 18:09:47",
        "revision": "fe826ed2ec0c",
        "runtimeVersion": "go1.16.3",
        "version": "v0.19.12"
    })";

    ziti_version ver;
    REQUIRE(parse_ziti_version(&ver, json, strlen(json)) > 0);
    REQUIRE(ver.api_versions != nullptr);
    auto v1Path = (api_path *) model_map_get(&ver.api_versions->edge, "v1");
    REQUIRE(v1Path);
    REQUIRE_THAT(v1Path->path, Catch::Equals("/edge/v1"));

    free_ziti_version(&ver);
}

TEST_CASE("parse-ziti-address", "[model]") {
    const char *j = R"("foo.bar")";
    ziti_address addr;

    int rc = parse_ziti_address(&addr, j, strlen(j));
    CHECK(rc > 0);
    CHECK(addr.type == ziti_address_hostname);
    CHECK_THAT(addr.addr.hostname, Catch::Equals("foo.bar"));
}

TEST_CASE("parse-ziti-intercept1", "[model]") {
    const char *json = R"( {
        "addresses": ["foo.bar", "1.1.1.1", "100.64.0.0/10", "ff::1/64"]
    })";

    char addr_str[64];
    ziti_intercept_cfg_v1 intercept;
    int len = parse_ziti_intercept_cfg_v1(&intercept, json, strlen(json));
    REQUIRE(len > 0);
    REQUIRE(intercept.addresses != nullptr);

    int idx = 0;
    CHECK(intercept.addresses[idx]->type == ziti_address_hostname);
    CHECK_THAT(intercept.addresses[idx]->addr.hostname, Catch::Equals("foo.bar"));

    idx++;
    CHECK(intercept.addresses[idx]->type == ziti_address_cidr);
    CHECK(intercept.addresses[idx]->addr.cidr.bits == 32);
    CHECK(intercept.addresses[idx]->addr.cidr.af == AF_INET);
    CHECK(uv_inet_ntop(intercept.addresses[idx]->addr.cidr.af, &intercept.addresses[idx]->addr.cidr.ip, addr_str, sizeof(addr_str)) == 0);
    CHECK_THAT(addr_str, Catch::Equals("1.1.1.1"));

    idx++;
    CHECK(intercept.addresses[idx]->type == ziti_address_cidr);
    CHECK(intercept.addresses[idx]->addr.cidr.bits == 10);
    CHECK(intercept.addresses[idx]->addr.cidr.af == AF_INET);
    CHECK(uv_inet_ntop(intercept.addresses[idx]->addr.cidr.af, &intercept.addresses[idx]->addr.cidr.ip, addr_str, sizeof(addr_str)) == 0);
    CHECK_THAT(addr_str, Catch::Equals("100.64.0.0"));

    idx++;
    CHECK(intercept.addresses[idx]->type == ziti_address_cidr);
    CHECK(intercept.addresses[idx]->addr.cidr.bits == 64);
    CHECK(intercept.addresses[idx]->addr.cidr.af == AF_INET6);
    CHECK(uv_inet_ntop(intercept.addresses[idx]->addr.cidr.af, &intercept.addresses[idx]->addr.cidr.ip, addr_str, sizeof(addr_str)) == 0);
    CHECK_THAT(addr_str, Catch::Equals("ff::1"));

    auto json_out = ziti_intercept_cfg_v1_to_json(&intercept, MODEL_JSON_COMPACT, nullptr);
    Catch::cout() << json_out;
    free_ziti_intercept_cfg_v1(&intercept);
    free(json_out);
}

TEST_CASE("ziti-address-match", "[model]") {

    const char *json = R"( {
        "addresses": ["foo.bar", "*.ziti", "*.yahoo.com", "1.1.1.1", "100.64.0.0/10", "ff::1/64"]
    })";

    ziti_intercept_cfg_v1 intercept;
    int len = parse_ziti_intercept_cfg_v1(&intercept, json, strlen(json));
    REQUIRE(len > 0);
    REQUIRE(intercept.addresses != nullptr);

    CHECK(ziti_address_match_array("foo.bar", intercept.addresses));
    CHECK(!ziti_address_match_array("foo.baz", intercept.addresses));
    CHECK(ziti_address_match_array("AWESOME.ZITI", intercept.addresses));
    CHECK(ziti_address_match_array("Yahoo.COM", intercept.addresses));
    CHECK(ziti_address_match_array("1.1.1.1", intercept.addresses));
    CHECK(!ziti_address_match_array("1.1.1.2", intercept.addresses));
    CHECK(ziti_address_match_array("100.127.1.1", intercept.addresses));
    CHECK(!ziti_address_match_array("100.128.1.2", intercept.addresses));
    CHECK(ziti_address_match_array("ff::abcd:1", intercept.addresses));
    CHECK(!ziti_address_match_array("ff:abcd::1", intercept.addresses));

    free_ziti_intercept_cfg_v1(&intercept);
}