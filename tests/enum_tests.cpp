/*
Copyright (c) 2021 NetFoundry, Inc.

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

#include <ziti/model_support.h>

#define States(XX,...)\
XX(Good, __VA_ARGS__) \
XX(Bad, __VA_ARGS__) \
XX(Ugly, __VA_ARGS__)

DECLARE_ENUM(State, States)
IMPL_ENUM(State, States)

TEST_CASE("test enum", "[model]") {
    State good = States.value_of("Good");

    CHECK(good == States.Good);
    CHECK_THAT(States.name(good), Catch::Matches("Good"));
}

#define ModelWithEnum(XX, ...) \
XX(name, string, none, name, __VA_ARGS__) \
XX(state, State, none, state, __VA_ARGS__)

DECLARE_MODEL(FooWithEnum, ModelWithEnum)
IMPL_MODEL(FooWithEnum, ModelWithEnum)

TEST_CASE("parse enum", "[model]") {
    const char *json = R"({
"name": "this is a name",
"state": "Ugly"
})";

    FooWithEnum f1;
    REQUIRE(parse_FooWithEnum(&f1, json, strlen(json)) == 0);

    CHECK_THAT(f1.name, Catch::Equals("this is a name"));
    CHECK(f1.state == States.Ugly);
}

TEST_CASE("enum to json", "[model]") {
    FooWithEnum f;
    f.name = (char *) "awesome foo";
    f.state = States.Bad;

    char *json = FooWithEnum_to_json(&f, 0, nullptr);

    REQUIRE(json);

    REQUIRE_THAT(json, Catch::Contains("\"state\":\"Bad\""));
    free(json);
}

TEST_CASE("enum compare", "[model]") {
    FooWithEnum f1,f2;
    f1.name = (char*)"awesome";
    f2.name = f1.name;
    f1.state = States.Bad;
    f2.state = States.Bad;

    CHECK(cmp_FooWithEnum(&f1, &f2) == 0);

    f2.state = States.Good;
    CHECK(cmp_FooWithEnum(&f1, &f2) > 0);
    CHECK(cmp_FooWithEnum(&f2, &f1) < 0);
}