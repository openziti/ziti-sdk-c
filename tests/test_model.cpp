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

#include "ziti_model.h"

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

    ziti_net_session *s = parse_ziti_net_session(ns, (int)strlen(ns));

    dump_ziti_net_session(s, 0);

    REQUIRE(s->edge_routers[0] != nullptr);
    REQUIRE(s->edge_routers[1] != nullptr);
    REQUIRE(s->edge_routers[2] == nullptr);

    REQUIRE(strcmp(s->edge_routers[1]->url_tls, "tls://ec2-18-188-224-88.us-east-2.compute.amazonaws.com:3022") == 0);

    free_ziti_net_session(s);
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
                       "    \"dns\": {\n"
                       "      \"hostname\": \"httpbin.org\",\n"
                       "      \"port\": 80\n"
                       "    },\n"
                       "    \"endpointAddress\": \"tcp:httpbin.org:80\",\n"
                       "    \"egressRouter\": \"1bcefeb5-6385-42e4-bd92-be1085825b58\",\n"
                       "    \"edgeRouterRoles\": null,\n"
                       "    \"roleAttributes\": null,\n"
                       "    \"permissions\": [\n"
                       "      \"Dial\"\n"
                       "    ]\n"
                       "  }"
                       "]";

    ziti_service** services = parse_ziti_service_array(json, (int)strlen(json));
    ziti_service **s;
    int idx;

    for (idx = 0, s = services; *s != nullptr; s++, idx++) {
        printf ("service #%d: %s\n", idx, (*s)->name);
        dump_ziti_service(services[idx], 2);
    }
    REQUIRE(idx == 2);
    REQUIRE(services[idx] == nullptr);

    REQUIRE_THAT(services[0]->name, Equals("hosting"));
    REQUIRE(services[0]->dns_port == 80);
    REQUIRE_THAT(services[0]->permissions[0], Equals("Bind"));

    REQUIRE(strcmp(services[1]->name, "httpbin") == 0);
    REQUIRE(services[1]->dns_port == 80);
    REQUIRE_THAT(services[1]->permissions[0], Equals("Dial"));

    free_ziti_service_array(services);
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

    ziti_session *session = parse_ziti_session(json, (int)strlen(json));

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

    ziti_error *err = parse_ziti_error(json, (int)strlen(json));
    REQUIRE_THAT(err->code, Equals("UNAUTHORIZED"));
}
