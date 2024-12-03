// Copyright (c) 2021-2023.  NetFoundry Inc.
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


#include "catch2_includes.hpp"

#include <ziti/model_support.h>

#define States(XX,...)\
XX(Good, __VA_ARGS__) \
XX(Bad, __VA_ARGS__) \
XX(Ugly, __VA_ARGS__)

DECLARE_ENUM(State, States)
IMPL_ENUM(State, States)

TEST_CASE("test enum", "[model]") {
    State good = States.value_of("Good");

    CHECK(State_Unknown == 0);
    CHECK(good == States.Good);
    CHECK_THAT(States.name(good), Catch::Matchers::Matches("Good"));
}

#define ModelWithEnum(XX, ...) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(state, State, none, state, __VA_ARGS__)

DECLARE_MODEL(FooWithEnum, ModelWithEnum)
IMPL_MODEL(FooWithEnum, ModelWithEnum)

TEST_CASE("parse enum", "[model]") {
    const char *json = R"({
"name": "this is a name",
"state": "Ugly"
})";

    FooWithEnum f1;
    REQUIRE(parse_FooWithEnum(&f1, json, strlen(json)) == strlen(json));

    CHECK_THAT(f1.name, Catch::Matchers::Equals("this is a name"));
    CHECK(f1.state == States.Ugly);

    free_FooWithEnum(&f1);
}

TEST_CASE("parse null enum", "[model]") {
    const char *json = R"({
"name": "this is a name",
"state": null
})";

    FooWithEnum f1;
    REQUIRE(parse_FooWithEnum(&f1, json, strlen(json)) == strlen(json));

    CHECK_THAT(f1.name, Catch::Matchers::Equals("this is a name"));
    CHECK(f1.state == 0);

    free_FooWithEnum(&f1);
}

TEST_CASE("default enum", "[model]") {
    FooWithEnum f = {0};
    f.name = (char *) "awesome foo";

    CHECK(f.state == State_Unknown);

    char *json = FooWithEnum_to_json(&f, 0, nullptr);

    REQUIRE(json);

    REQUIRE_THAT(json, Catch::Matchers::ContainsSubstring("\"state\":null"));

    FooWithEnum f2;
    REQUIRE(parse_FooWithEnum(&f2, json, strlen(json)) == strlen(json));
    CHECK(f2.state == State_Unknown);

    free_FooWithEnum(&f2);
    free(json);
}

TEST_CASE("enum to json", "[model]") {
    FooWithEnum f = {0};
    f.name = (char *) "awesome foo";
    f.state = States.Bad;

    char *json = FooWithEnum_to_json(&f, 0, nullptr);

    REQUIRE(json);

    REQUIRE_THAT(json, Catch::Matchers::ContainsSubstring("\"state\":\"Bad\""));
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

#define ModelWithEnumArray(XX, ...) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(states, State, array, states, __VA_ARGS__)

DECLARE_MODEL(FooWithEnumArray, ModelWithEnumArray)
IMPL_MODEL(FooWithEnumArray, ModelWithEnumArray)

TEST_CASE("parse enum array", "[model]") {
    const char *json = R"({
"name": "this is a name",
"states": ["Ugly", "Bad"]
})";

    FooWithEnumArray f1;
    REQUIRE(parse_FooWithEnumArray(&f1, json, strlen(json)) == strlen(json));

    CHECK_THAT(f1.name, Catch::Matchers::Equals("this is a name"));
    CHECK(*f1.states[0] == States.Ugly);
    CHECK(*f1.states[1] == States.Bad);
    CHECK(f1.states[2] == nullptr);

    size_t json_len;
    auto js = FooWithEnumArray_to_json(&f1, MODEL_JSON_COMPACT, &json_len);

    CHECK_THAT(js, Catch::Matchers::ContainsSubstring(R"("states":["Ugly","Bad"])"));

    free_FooWithEnumArray(&f1);
    free(js);
}

#define ModelWithEnumList(XX, ...) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(states, State, list, states, __VA_ARGS__)

DECLARE_MODEL(FooWithEnumList, ModelWithEnumList)

IMPL_MODEL(FooWithEnumList, ModelWithEnumList)

TEST_CASE("parse enum list", "[model]") {
    const char *json = R"({
"name": "this is a name",
"states": ["Ugly", "Bad"]
})";

    FooWithEnumList f1;
    REQUIRE(parse_FooWithEnumList(&f1, json, strlen(json)) == strlen(json));

    CHECK_THAT(f1.name, Catch::Matchers::Equals("this is a name"));
    auto it = model_list_iterator(&f1.states);
    CHECK(*(State *) model_list_it_element(it) == States.Ugly);
    it = model_list_it_next(it);
    CHECK(*(State *) model_list_it_element(it) == States.Bad);
    CHECK(model_list_it_next(it) == nullptr);


    size_t json_len;
    auto js = FooWithEnumList_to_json(&f1, MODEL_JSON_COMPACT, &json_len);

    CHECK_THAT(js, Catch::Matchers::ContainsSubstring(R"("states":["Ugly","Bad"])"));

    free_FooWithEnumList(&f1);
    free(js);
}