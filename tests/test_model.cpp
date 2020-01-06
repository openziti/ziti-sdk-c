/*
Copyright 2019-2020 Netfoundry, Inc.

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
#include <string.h>

#if _WIN32
#include <windows.h>
#define timegm(v) _mkgmtime(v)
#define gmtime(v) _gmtime32(v)
#else
#define _GNU_SOURCE //add time.h include after defining _GNU_SOURCE
#include <time.h>
#endif

#include "../library/model.h"

using Catch::Matchers::Equals;

TEST_CASE("multi-gateway session", "[model]") {

    const char *ns = "{\n"
                     "    \"_links\": {\n"
                     "      \"self\": {\n"
                     "        \"href\": \"./network-sessions/1276df75-3ba3-4658-98ad-fe5a0e96021a\"\n"
                     "      }\n"
                     "    },\n"
                     "    \"gateways\": [\n"
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

    REQUIRE(s->gateways[0] != nullptr);
    REQUIRE(s->gateways[1] != nullptr);
    REQUIRE(s->gateways[2] == nullptr);

    REQUIRE(strcmp(s->gateways[1]->url_tls, "tls://ec2-18-188-224-88.us-east-2.compute.amazonaws.com:3022") == 0);

    free_ziti_net_session(s);
}

TEST_CASE("parse-services-array", "[model]") {
    const char *json = "[\n"
                     "        {\n"
                     "            \"_links\": {\n"
                     "                \"clusters\": {\n"
                     "                    \"href\": \"./services/b67f9870-8d07-4177-be05-c0cba699e84d/clusters\"\n"
                     "                }, \n"
                     "                \"self\": {\n"
                     "                    \"href\": \"./services/b67f9870-8d07-4177-be05-c0cba699e84d\"\n"
                     "                }\n"
                     "            }, \n"
                     "            \"clusters\": [\n"
                     "                {\n"
                     "                    \"_links\": {\n"
                     "                        \"gateways\": {\n"
                     "                            \"href\": \"./clusters/6cd04fd4-10e3-455e-893d-b71c3c530603/gateways\"\n"
                     "                        }, \n"
                     "                        \"self\": {\n"
                     "                            \"href\": \"./clusters/6cd04fd4-10e3-455e-893d-b71c3c530603\"\n"
                     "                        }\n"
                     "                    }, \n"
                     "                    \"createdAt\": \"2019-01-21T14:28:52.986383Z\", \n"
                     "                    \"id\": \"6cd04fd4-10e3-455e-893d-b71c3c530603\", \n"
                     "                    \"name\": \"azure\", \n"
                     "                    \"tags\": {}, \n"
                     "                    \"updatedAt\": \"2019-08-22T21:20:51.611174Z\"\n"
                     "                }\n"
                     "            ], \n"
                     "            \"createdAt\": \"2019-02-27T21:58:04.574338Z\", \n"
                     "            \"dns\": {\n"
                     "                \"hostname\": \"demosecuredfunction.azurewebsites.net\", \n"
                     "                \"port\": 443\n"
                     "            }, \n"
                     "            \"egressRouter\": \"unknown\", \n"
                     "            \"endpointAddress\": null, \n"
                     "            \"hostable\": true, \n"
                     "            \"id\": \"b67f9870-8d07-4177-be05-c0cba699e84d\", \n"
                     "            \"legacyPassthrough\": false, \n"
                     "            \"name\": \"Azure-Ping\", \n"
                     "            \"tags\": {}, \n"
                     "            \"updatedAt\": \"2019-02-27T21:58:04.574338Z\"\n"
                     "        }, \n"
                     "        {\n"
                     "            \"_links\": {\n"
                     "                \"clusters\": {\n"
                     "                    \"href\": \"./services/1ab83c54-9024-4486-8e33-b117f7f64435/clusters\"\n"
                     "                }, \n"
                     "                \"self\": {\n"
                     "                    \"href\": \"./services/1ab83c54-9024-4486-8e33-b117f7f64435\"\n"
                     "                }\n"
                     "            }, \n"
                     "            \"clusters\": [\n"
                     "                {\n"
                     "                    \"_links\": {\n"
                     "                        \"gateways\": {\n"
                     "                            \"href\": \"./clusters/6cd04fd4-10e3-455e-893d-b71c3c530603/gateways\"\n"
                     "                        }, \n"
                     "                        \"self\": {\n"
                     "                            \"href\": \"./clusters/6cd04fd4-10e3-455e-893d-b71c3c530603\"\n"
                     "                        }\n"
                     "                    }, \n"
                     "                    \"createdAt\": \"2019-01-21T14:28:52.986383Z\", \n"
                     "                    \"id\": \"6cd04fd4-10e3-455e-893d-b71c3c530603\", \n"
                     "                    \"name\": \"azure\", \n"
                     "                    \"tags\": {}, \n"
                     "                    \"updatedAt\": \"2019-08-22T21:20:51.611174Z\"\n"
                     "                }\n"
                     "            ], \n"
                     "            \"createdAt\": \"2019-07-29T17:03:42.85819Z\", \n"
                     "            \"dns\": {\n"
                     "                \"hostname\": \"wttr.in\", \n"
                     "                \"port\": 80\n"
                     "            }, \n"
                     "            \"egressRouter\": \"unknown\", \n"
                     "            \"endpointAddress\": null, \n"
                     "            \"hostable\": false, \n"
                     "            \"id\": \"1ab83c54-9024-4486-8e33-b117f7f64435\", \n"
                     "            \"legacyPassthrough\": false, \n"
                     "            \"name\": \"wttr.in-80\", \n"
                     "            \"tags\": {}, \n"
                     "            \"updatedAt\": \"2019-08-05T14:02:52.337619Z\"\n"
                     "        }] ";

    ziti_service** services = parse_ziti_service_array(json, (int)strlen(json));
    ziti_service **s;
    int idx;
    for (idx = 0, s = services; *s != nullptr; s++, idx++) {
        printf ("service #%d: %s\n", idx, (*s)->name);
        dump_ziti_service(services[idx], 2);
    }

    REQUIRE(idx == 2);
    REQUIRE(strcmp(services[0]->name, "Azure-Ping") == 0);
    REQUIRE(services[0]->dns_port == 443);
    REQUIRE(services[0]->hostable);
    REQUIRE(strcmp(services[1]->name, "wttr.in-80") == 0);
    REQUIRE(services[1]->dns_port == 80);
    REQUIRE_FALSE(services[1]->hostable);
    REQUIRE(services[idx] == nullptr);

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