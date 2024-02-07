// Copyright (c) 2022-2023.  NetFoundry Inc.
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

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

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
#include "ziti/ziti.h"

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

    const char *session_json = R"(
{
  "_links": {
    "route-path": {
      "href": "./sessions/cls4w5p6w3nophj1hg3hh9grz/route-path"
    },
    "self": {
      "href": "./sessions/cls4w5p6w3nophj1hg3hh9grz"
    }
  },
  "createdAt": "2024-02-02T17:00:29.768Z",
  "id": "cls4w5p6w3nophj1hg3hh9grz",
  "tags": {},
  "updatedAt": "2024-02-02T17:00:29.768Z",
  "apiSession": {
    "_links": {
      "self": {
        "href": "./api-sessions/cls4w569t3nnwhj1h5gca2mtb"
      },
      "sessions": {
        "href": "./api-sessions/cls4w569t3nnwhj1h5gca2mtb/sessions"
      }
    },
    "entity": "api-sessions",
    "id": "cls4w569t3nnwhj1h5gca2mtb"
  },
  "apiSessionId": "cls4w569t3nnwhj1h5gca2mtb",
  "edgeRouters": [
    {
      "cost": 0,
      "disabled": false,
      "hostname": "eccfca4e-b9ea-45c4-a26c-f61ce2acf6f5.production.netfoundry.io",
      "isOnline": true,
      "name": "Mattermost-Public-Edge-aws-ashburn-us-east-1-1",
      "noTraversal": false,
      "supportedProtocols": {
        "tls": "tls://eccfca4e-b9ea-45c4-a26c-f61ce2acf6f5.production.netfoundry.io:443"
      },
      "syncStatus": "SYNC_DONE",
      "urls": {
        "tls": "tls://eccfca4e-b9ea-45c4-a26c-f61ce2acf6f5.production.netfoundry.io:443"
      }
    },
    {
      "cost": 0,
      "disabled": false,
      "hostname": "cd938be5-bd0b-48b3-8db8-67e4bf62eb10.production.netfoundry.io",
      "isOnline": true,
      "name": "Mattermost-Public-Edge-aws-mumbai-ap-south-1-1",
      "noTraversal": false,
      "supportedProtocols": {
        "tls": "tls://cd938be5-bd0b-48b3-8db8-67e4bf62eb10.production.netfoundry.io:443"
      },
      "syncStatus": "SYNC_DONE",
      "urls": {
        "tls": "tls://cd938be5-bd0b-48b3-8db8-67e4bf62eb10.production.netfoundry.io:443"
      }
    },
    {
      "cost": 0,
      "disabled": false,
      "hostname": "0886eaea-5d1a-440d-b1a2-1db9e6d5c04d.production.netfoundry.io",
      "isOnline": true,
      "name": "Mattermost-Public-Edge-aws-boardman-us-west-2-1",
      "noTraversal": false,
      "supportedProtocols": {
        "tls": "tls://0886eaea-5d1a-440d-b1a2-1db9e6d5c04d.production.netfoundry.io:443"
      },
      "syncStatus": "SYNC_DONE",
      "urls": {
        "tls": "tls://0886eaea-5d1a-440d-b1a2-1db9e6d5c04d.production.netfoundry.io:443"
      }
    }
  ],
  "identityId": "CKr13vQdE",
  "service": {
    "_links": {
      "configs": {
        "href": "./services/f.n.2z-Xe/configs"
      },
      "self": {
        "href": "./services/f.n.2z-Xe"
      },
      "service-edge-router-policies": {
        "href": "./services/f.n.2z-Xe/service-edge-router-policies"
      },
      "service-policies": {
        "href": "./services/f.n.2z-Xe/service-policies"
      },
      "terminators": {
        "href": "./services/f.n.2z-Xe/terminators"
      }
    },
    "entity": "services",
    "id": "f.n.2z-Xe",
    "name": "mattermost.tools.netfoundry.io"
  },
  "serviceId": "f.n.2z-Xe",
  "token": "f49bbb5c-4623-4ae0-9e88-b6ea226434dc",
  "type": "Dial"
})";
    ziti_session *s;
    REQUIRE(parse_ziti_session_ptr(&s, session_json, (int) strlen(session_json)) == strlen(session_json));

    REQUIRE(model_list_size(&s->edge_routers) == 3);

    auto it = model_list_iterator(&s->edge_routers);
    auto er = (ziti_edge_router *) model_list_it_element(it);
    auto tls = (const char *) model_map_get(&er->protocols, "tls");
    REQUIRE_THAT(tls, Catch::Matchers::Matches("tls://eccfca4e-b9ea-45c4-a26c-f61ce2acf6f5.production.netfoundry.io:443"));

    it = model_list_it_next(it);
    er = (ziti_edge_router *) model_list_it_element(it);
    tls = (const char *) model_map_get(&er->protocols, "tls");
    REQUIRE_THAT(tls, Catch::Matchers::Matches("tls://cd938be5-bd0b-48b3-8db8-67e4bf62eb10.production.netfoundry.io:443"));

    free_ziti_session(s);
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
    CHECK(ej.method == ziti_enrollment_methods.ott);
    CHECK_THAT(ej.controller, Equals("https://demo.ziti.netfoundry.io:1080"));
    CHECK_THAT(ej.subject, Equals("c17291f4-37fe-4cdb-9f57-3eb757b648f5"));
    CHECK_THAT(ej.token, Equals("f581d770-fffc-11e9-a81a-000d3a1b4b17"));
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
        model_list_iter it = model_list_iterator(&intercept.protocols);
        CHECK(*(ziti_protocol *) model_list_it_element(it) == ziti_protocols.tcp);
        it = model_list_it_next(it);
        CHECK(*(ziti_protocol *) model_list_it_element(it) == ziti_protocols.udp);
        CHECK(model_list_it_next(it) == nullptr);

        auto pr = (ziti_port_range *) model_list_head(&intercept.port_ranges);
        CHECK(pr->high == 80);
        CHECK(pr->low == 80);
        CHECK(model_list_size(&intercept.port_ranges) == 1);

        auto addr = (ziti_address *) model_list_head(&intercept.addresses);
        CHECK(addr->type == ziti_address_hostname);
        CHECK_THAT(addr->addr.hostname, Equals("hello.ziti"));
        CHECK(model_list_size(&intercept.addresses) == 1);

        free_ziti_client_cfg_v1(&cfg);
        free_ziti_intercept_cfg_v1(&intercept);
    }

    {
        ziti_intercept_cfg_v1 cfg;
        REQUIRE(ziti_service_get_config(&s, "intercept.v1", &cfg,
                                        (int (*)(void *, const char *, size_t)) (parse_ziti_intercept_cfg_v1)) == 0);

        CHECK(*(ziti_protocol *) model_list_head(&cfg.protocols) == ziti_protocols.tcp);
        ziti_address ip1_2_3_4;
        parse_ziti_address_str(&ip1_2_3_4, "1.2.3.4");
        CHECK(ziti_address_match((ziti_address *) model_list_head(&cfg.addresses), &ip1_2_3_4) == 0);
        auto pr = (ziti_port_range *) model_list_head(&cfg.port_ranges);
        CHECK(pr->high == 80);
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
    REQUIRE_THAT(v1Path->path, Catch::Matchers::Equals("/edge/v1"));

    free_ziti_version(&ver);
}

TEST_CASE("parse-ziti-address", "[model]") {
    const char *j = R"("foo.bar")";
    ziti_address addr;

    int rc = parse_ziti_address(&addr, j, strlen(j));
    CHECK(rc > 0);
    CHECK(addr.type == ziti_address_hostname);
    CHECK_THAT(addr.addr.hostname, Catch::Matchers::Equals("foo.bar"));
}

TEST_CASE("parse-ziti-intercept1", "[model]") {
    const char *json = R"( {
        "addresses": ["foo.bar", "1.1.1.1", "100.64.0.0/10", "ff::1/64"]
    })";

    char addr_str[64];
    ziti_intercept_cfg_v1 intercept;
    int len = parse_ziti_intercept_cfg_v1(&intercept, json, strlen(json));
    REQUIRE(len > 0);
    REQUIRE(model_list_size(&intercept.addresses) == 4);

    int idx = 0;
    model_list_iter it = model_list_iterator(&intercept.addresses);
    auto *addr = (ziti_address *) model_list_it_element(it);
    CHECK(addr->type == ziti_address_hostname);
    CHECK_THAT(addr->addr.hostname, Catch::Matchers::Equals("foo.bar"));

    it = model_list_it_next(it);
    addr = (ziti_address *) model_list_it_element(it);
    CHECK(addr->type == ziti_address_cidr);
    CHECK(addr->addr.cidr.bits == 32);
    CHECK(addr->addr.cidr.af == AF_INET);
    CHECK(uv_inet_ntop(addr->addr.cidr.af, &addr->addr.cidr.ip, addr_str, sizeof(addr_str)) == 0);
    CHECK_THAT(addr_str, Catch::Matchers::Equals("1.1.1.1"));

    it = model_list_it_next(it);
    addr = (ziti_address *) model_list_it_element(it);
    CHECK(addr->type == ziti_address_cidr);
    CHECK(addr->addr.cidr.bits == 10);
    CHECK(addr->addr.cidr.af == AF_INET);
    CHECK(uv_inet_ntop(addr->addr.cidr.af, &addr->addr.cidr.ip, addr_str, sizeof(addr_str)) == 0);
    CHECK_THAT(addr_str, Catch::Matchers::Equals("100.64.0.0"));

    it = model_list_it_next(it);
    addr = (ziti_address *) model_list_it_element(it);
    CHECK(addr->type == ziti_address_cidr);
    CHECK(addr->addr.cidr.bits == 64);
    CHECK(addr->addr.cidr.af == AF_INET6);
    CHECK(uv_inet_ntop(addr->addr.cidr.af, &addr->addr.cidr.ip, addr_str, sizeof(addr_str)) == 0);
    CHECK_THAT(addr_str, Catch::Matchers::Equals("ff::1"));

    auto json_out = ziti_intercept_cfg_v1_to_json(&intercept, MODEL_JSON_COMPACT, nullptr);
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

    CHECK(ziti_addrstr_match_list("foo.bar", &intercept.addresses) == 0);
    CHECK(ziti_addrstr_match_list("foo.baz", &intercept.addresses) == -1);
    CHECK(ziti_addrstr_match_list("AWESOME.ZITI", &intercept.addresses) > 0);
    CHECK(ziti_addrstr_match_list("Yahoo.COM", &intercept.addresses) >= 0);
    CHECK(ziti_addrstr_match_list("1.1.1.1", &intercept.addresses) == 0);
    CHECK(ziti_addrstr_match_list("1.1.1.2", &intercept.addresses) == -1);
    CHECK(ziti_addrstr_match_list("100.127.1.1", &intercept.addresses) == 22); // match 100.64.0.0/10
    CHECK(ziti_addrstr_match_list("100.128.1.2", &intercept.addresses) == -1);
    CHECK(ziti_addrstr_match_list("ff::abcd:1", &intercept.addresses) > 0);
    CHECK(ziti_addrstr_match_list("ff:abcd::1", &intercept.addresses) == -1);

    free_ziti_intercept_cfg_v1(&intercept);
}

TEST_CASE("ziti-intercept_test", "[model]") {
    ziti_client_cfg_v1 cltV1;
    REQUIRE(parse_ziti_address_str(&cltV1.hostname, "httpbin.ziti") == 0);
    cltV1.port = 80;

    ziti_intercept_cfg_v1 interceptCfgV1;
    REQUIRE(ziti_intercept_from_client_cfg(&interceptCfgV1, &cltV1) == 0);
    REQUIRE(model_list_size(&interceptCfgV1.addresses) == 1);

    free_ziti_intercept_cfg_v1(&interceptCfgV1);
    free_ziti_client_cfg_v1(&cltV1);
}

TEST_CASE("load cfg", "[model]") {
    auto good_json = R"({
  "ztAPI": "https://calculon.local:1280",
  "id": {
    "cert": "-----BEGIN CERTIFICATE-----\nMIIDnjCCAYagAwIBAgIDBirVMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT\nMRIwEAYDVQQHEwlDaGFybG90dGUxEzARBgNVBAoTCk5ldEZvdW5kcnkxEDAOBgNV\nBAsTB0FEVi1ERVYxGDAWBgNVBAMTD2ludGVybWVkaWF0ZS1jYTAeFw0yMzEyMDQx\nOTI2MTBaFw0yNDEyMDQxOTI3MTBaMEIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJO\nWTERMA8GA1UEChMIT3BlblppdGkxEzARBgNVBAMTCjVZTENuUGtEcUMwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASAQAB1dYikr3YetRN6dLnGz8pWpp5nna/ErGTV\nZAP1nAHykTdrZCjt1dBv8xHxsbF0drT/Ddzyn/HeQdx3SFHbo0gwRjAOBgNVHQ8B\nAf8EBAMCBLAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHwYDVR0jBBgwFoAUME5gfYO0\n2JAM0WNdLGVOg5JXAHIwDQYJKoZIhvcNAQELBQADggIBAEfW6quMT1Uok/3sbBT2\n+sYeFYigknDtFNTDpyKz2aM03iBYdOGGDnzc/8klwvI/LgOBq9RW6F9ySHl9UdYr\nBeeq2+wlth4Wks+imlmhFw+WafMi94Ly8yk/vQImud17PfGcr78gn+6EaSUevNpk\nT0oq27AxGzYJyIa9c62VCiavPrE2rXVKbFm7CiIr7u1K4+obrf57kS5hPZ4Yxfd+\nTcW8jBhS4aSmwSYjd/qTV9T25jylS/RWe1EvneGvW0DMFvW9l1KfrhS+JKnEaMTW\ndtEfcWcr8Nio7GyPS6OYC48euLqy0TcUDmQXVE/u4tjmngzqlZKAC9Fyc82V4ouj\nyV1F3JMEUwPZfLfWj5/7Nq/mqPGfK1SQAX70vkGE8Ac3zzCtSRCdxrkEvGMaoy2o\ny5iqFd+RFJuo02rmQj/Y4h7ewPCFpofJ60ytQVh29kq7nHM7yJlm/jbrV0z0lWHm\nBVfarXbODeMEweN9J22VB7O3QzHTZUZmKpcRPJVbIDGySVYZRr4/4SkR5AU9SPv5\nowYhD7LPfsgowPE+1bE16eoZLeOwyPUvUfblZJ79LSQb9HFvL6fMTufMgaCQrcb6\nZqjv+0fm+lxhrrgwDVAQE0/0NK5cM6F6jNr0wJJhUsrss6gRr9jA3KcRJZJzknWh\nace4f9yDr6iJ2jUN9y6rAxpq\n-----END CERTIFICATE-----\n",
    "key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRZiIMpgWJy6d3wGh\n2mdOsAGZwZ05hhm6NPlaFzU8hQihRANCAASAQAB1dYikr3YetRN6dLnGz8pWpp5n\nna/ErGTVZAP1nAHykTdrZCjt1dBv8xHxsbF0drT/Ddzyn/HeQdx3SFHb\n-----END PRIVATE KEY-----\n",
    "ca": "-----BEGIN CERTIFICATE-----\n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\nNSJO51hD\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----\n"
  }
}
)";
    auto bad_json = R"({
  "ztAPI": "https://calculon.local:1280",
  "id": {
    "cert": "-----BEGIN CERTIFICATE-----\nMIIDnjCCAYagAwIBAgIDBirVMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT\nMRIwEAYDVQQHEwlDaGFybG90dGUxEzARBgNVBAoTCk5ldEZvdW5kcnkxEDAOBgNV\nBAsTB0FEVi1ERVYxGDAWBgNVBAMTD2ludGVybWVkaWF0ZS1jYTAeFw0yMzEyMDQx\nOTI2MTBaFw0yNDEyMDQxOTI3MTBaMEIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJO\nWTERMA8GA1UEChMIT3BlblppdGkxEzARBgNVBAMTCjVZTENuUGtEcUMwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASAQAB1dYikr3YetRN6dLnGz8pWpp5nna/ErGTV\nZAP1nAHykTdrZCjt1dBv8xHxsbF0drT/Ddzyn/HeQdx3SFHbo0gwRjAOBgNVHQ8B\nAf8EBAMCBLAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHwYDVR0jBBgwFoAUME5gfYO0\n2JAM0WNdLGVOg5JXAHIwDQYJKoZIhvcNAQELBQADggIBAEfW6quMT1Uok/3sbBT2\n+sYeFYigknDtFNTDpyKz2aM03iBYdOGGDnzc/8klwvI/LgOBq9RW6F9ySHl9UdYr\nBeeq2+wlth4Wks+imlmhFw+WafMi94Ly8yk/vQImud17PfGcr78gn+6EaSUevNpk\nT0oq27AxGzYJyIa9c62VCiavPrE2rXVKbFm7CiIr7u1K4+obrf57kS5hPZ4Yxfd+\nTcW8jBhS4aSmwSYjd/qTV9T25jylS/RWe1EvneGvW0DMFvW9l1KfrhS+JKnEaMTW\ndtEfcWcr8Nio7GyPS6OYC48euLqy0TcUDmQXVE/u4tjmngzqlZKAC9Fyc82V4ouj\nyV1F3JMEUwPZfLfWj5/7Nq/mqPGfK1SQAX70vkGE8Ac3zzCtSRCdxrkEvGMaoy2o\ny5iqFd+RFJuo02rmQj/Y4h7ewPCFpofJ60ytQVh29kq7nHM7yJlm/jbrV0z0lWHm\nBVfarXbODeMEweN9J22VB7O3QzHTZUZmKpcRPJVbIDGySVYZRr4/4SkR5AU9SPv5\nowYhD7LPfsgowPE+1bE16eoZLeOwyPUvUfblZJ79LSQb9HFvL6fMTufMgaCQrcb6\nZqjv+0fm+lxhrrgwDVAQE0/0NK5cM6F6jNr0wJJhUsrss6gRr9jA3KcRJZJzknWh\nace4f9yDr6iJ2jUN9y6rAxpq\n-----END CERTIFICATE-----\n",
)";

    auto non_identity_json = R"({
    "foo": "bar"
})";

    ziti_config cfg;
    REQUIRE(ziti_load_config(&cfg, nullptr) == ZITI_INVALID_CONFIG);

    REQUIRE(ziti_load_config(&cfg, good_json) == ZITI_OK);
    free_ziti_config(&cfg);

    REQUIRE(ziti_load_config(&cfg, bad_json) == ZITI_CONFIG_NOT_FOUND);
    free_ziti_config(&cfg);

    REQUIRE(ziti_load_config(&cfg, non_identity_json) == ZITI_INVALID_CONFIG);
    free_ziti_config(&cfg);
}