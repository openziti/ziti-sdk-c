// Copyright (c) 2020-2022.  NetFoundry Inc.
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

#include <cstring>
#include <string>
#include <vector>
#include "catch2_includes.hpp"
#include <catch2/generators/catch_generators.hpp>

#include <ziti/model_support.h>
#include <iostream>
#include <tuple>

#include <json-c/json.h>

#include <zt_cstr.h>

#define BAR_MODEL(xx, ...)\
xx(num, model_number, none, num, __VA_ARGS__)\
xx(nump, model_number, ptr, nump, __VA_ARGS__) \
xx(isOK, model_bool, none, ok, __VA_ARGS__)\
xx(msg, model_string, none, msg, __VA_ARGS__)\
xx(ts, timestamp, ptr, time, __VA_ARGS__)\
xx(errors, model_string, array, errors, __VA_ARGS__)\
xx(codes, model_number, array, codes, __VA_ARGS__)\
xx(shoes, model_string, list, shoes, __VA_ARGS__)

DECLARE_MODEL(Bar, BAR_MODEL)

IMPL_MODEL(Bar, BAR_MODEL)

#define FOO_MODEL(xx, ...) \
xx(bar, Bar, none, bar, __VA_ARGS__) \
xx(barp, Bar, ptr, barp, __VA_ARGS__) \
xx(bar_arr, Bar, array, bara, __VA_ARGS__)

DECLARE_MODEL(Foo, FOO_MODEL)

IMPL_MODEL(Foo, FOO_MODEL)

using namespace Catch::Matchers;

#define BAR1 "{\
\"num\":42,\
\"ok\": false,\
\"time\": \"2020-07-20T14:14:14.666666Z\",\
\"msg\":\"this is a message\",\
\"errors\": [\"error1\", \"error2\"], \
\"codes\": [401, 403], \
\"shoes\": [ \"sandals\", \"slippers\", \"boots\" ] \
}"

#define BAR_WITH_NULL_CODES_ARRAY "{\
\"num\":42,\
\"ok\": false,\
\"time\": \"2020-07-20T14:14:14.666666Z\",\
\"msg\":\"this is a message\",\
\"errors\": [\"error1\", \"error2\"], \
\"codes\": null, \
\"shoes\": null \
}"

#define BAR_WITH_MISSING_CODES_ARRAY "{\
\"num\":42,\
\"ok\": false,\
\"time\": \"2020-07-20T14:14:14.666666Z\",\
\"msg\":\"this is a message\",\
\"errors\": [\"error1\", \"error2\"] \
}"

static inline std::string remove_space(const char* s) {
    std::string r(s);
    auto end = std::remove_if(r.begin(), r.end(), isspace);
    r.erase(end, r.end());
    return r;
}

static void checkBar1(const Bar &bar) {
    CHECK(bar.num == 42);
    CHECK(!bar.isOK);
    CHECK_THAT(bar.errors[0], Equals("error1"));
    CHECK_THAT(bar.errors[1], Equals("error2"));
    CHECK(bar.errors[2] == nullptr);

    int c1 = *bar.codes[0];
    CHECK(c1 == 401);
    int c2 = *bar.codes[1];
    CHECK(c2 == 403);
    CHECK(bar.codes[2] == nullptr);
}

#define BAR2 "{\
\"num\":-42,\
\"ok\": true,\
}"

static void checkBar2(const Bar &bar) {
    CHECK(bar.num == -42);
    CHECK(bar.isOK);
    CHECK(bar.errors == nullptr);
    CHECK(bar.codes == nullptr);
}

TEST_CASE("new model tests", "[model]") {
    const char *bar_json = BAR1;
    Bar bar;

    REQUIRE(parse_Bar(&bar, bar_json, strlen(bar_json)) == strlen(bar_json));

    checkBar1(bar);

    auto json = Bar_to_json(&bar, 0, nullptr);
    CHECK(json != nullptr);
    std::cout << json << std::endl;
    free(json);
    free_Bar(&bar);

    auto j = json_tokener_parse(bar_json);
    REQUIRE(Bar_from_json(&bar, j) == 0);
    checkBar1(bar);
    json_object_put(j);

    json = Bar_to_json(&bar, 0, nullptr);
    std::cout << json << std::endl;
    free(json);
    free_Bar(&bar);
}

TEST_CASE("parse null", "[model]") {
    const char *json = "{"
                       "\"barp\":null,"
                       "\"bara\":null"
                       "}";
    Foo foo;
    REQUIRE(parse_Foo(&foo, json, strlen(json)) == strlen(json));

    REQUIRE(foo.barp == nullptr);

    REQUIRE(foo.bar_arr == nullptr);

    char *json1 = Foo_to_json(&foo, 0, NULL);
    std::cout << json1 << std::endl;
    free(json1);
    free_Foo(&foo);
}

TEST_CASE("parse null in the middle", "[model]") {
    const char *json = "{"
                       "\"bar\":" BAR1 ","
                       "\"barp\": null,"
                       "\"bara\": [" BAR1 "," BAR2 "]"
                       "}";
    Foo foo;
    REQUIRE(parse_Foo(&foo, json, strlen(json)) == strlen(json));
    checkBar1(foo.bar);

    REQUIRE(foo.barp == nullptr);

    REQUIRE(foo.bar_arr != nullptr);
    CHECK(foo.bar_arr[2] == nullptr);
    checkBar1(*foo.bar_arr[0]);
    checkBar2(*foo.bar_arr[1]);

    char *json1 = Foo_to_json(&foo, 0, NULL);
    std::cout << json1 << std::endl;
    free(json1);
    free_Foo(&foo);
}
TEST_CASE("embedded struct", "[model]") {
    const char *json = "{"
                       "\"bar\":" BAR1 ","
                       "\"barp\": " BAR2 ","
                       "\"bara\": [" BAR1 "," BAR2 "]"
                       "}";
    Foo foo;
    REQUIRE(parse_Foo(&foo, json, strlen(json)) == strlen(json));
    checkBar1(foo.bar);

    REQUIRE(foo.barp != nullptr);
    checkBar2(*foo.barp);

    REQUIRE(foo.bar_arr != nullptr);
    CHECK(foo.bar_arr[2] == nullptr);
    checkBar1(*foo.bar_arr[0]);
    checkBar2(*foo.bar_arr[1]);

    char *json1 = Foo_to_json(&foo, 0, NULL);
    std::cout << json1 << std::endl;
    free(json1);
    free_Foo(&foo);
}

TEST_CASE("test skipped fields", "[model]") {
    const char *json = R"({
        "bar":{
            "num":42,
            "ok":true,
            "msg":"hello\nworld!"
        },
        "skipper": [{"this":"should be skipped"},42,null],
        "also-skip": {"more":"skipping"},
        "barp":{
            "skip-field":{},
            "nump":42,
            "ok":true,
            "msg":"hello world!"
        }
    })";
    Foo foo;
    REQUIRE(parse_Foo(&foo, json, strlen(json)) == strlen(json));

    REQUIRE(foo.bar.num == 42);
    REQUIRE(foo.bar.isOK);
    REQUIRE_THAT(foo.bar.msg, Catch::Matchers::Equals("hello\nworld!"));

    REQUIRE(foo.barp != nullptr);
    REQUIRE(*foo.barp->nump == 42);
    REQUIRE(foo.barp->isOK);
    REQUIRE_THAT(foo.barp->msg, Catch::Matchers::Equals("hello world!"));

    size_t jsonlen;
    char *json1 = Foo_to_json(&foo, 0, &jsonlen);
    std::cout << json1 << std::endl;
    free(json1);
    free_Foo(&foo);
}

TEST_CASE("test string escape", "[model]") {
    const char *json = R"({
        "msg":"\thello\n\"world\"!"
    })";

    Bar bar;
    REQUIRE(parse_Bar(&bar, json, strlen(json)) == strlen(json));
    REQUIRE_THAT(bar.msg, Equals("\thello\n\"world\"!"));

    char *jsonout = Bar_to_json(&bar, 0, NULL);
    std::cout << jsonout << std::endl;
    free(jsonout);
    free_Bar(&bar);
}

TEST_CASE("parse array", "[model]") {
    const char *json = R"([{
        "msg":"\thello\n\"world\"!"
    },
    {"msg":"Hello again!"}])";

    Bar_array bars = nullptr;
    int rc = parse_Bar_array(&bars, json, strlen(json));
    CHECK(rc == strlen(json));
    CHECK_THAT(bars[0]->msg, Catch::Matchers::Matches("\thello\n\"world\"!"));
    CHECK_THAT(bars[1]->msg, Catch::Matchers::Matches("Hello again!"));
    free_Bar_array(&bars);
}

TEST_CASE("parse bad array", "[model]") {
    const char *json = R"([{
        "msg":"\thello\n\"world\"!"
    },
    {"msg":56}])";

    Bar_array bars = nullptr;
    int rc = parse_Bar_array(&bars, json, strlen(json));
    CHECK(rc == -1);
    CHECK(bars == nullptr);
}

TEST_CASE("parse 2 objects in string ", "[model]") {
    const char *json = R"({
        "msg":"\thello\n\"world\"!"
    }{"msg":"Hello again!"})";

    Bar bar = {0};
    int rc = parse_Bar(&bar, json, strlen(json));
    REQUIRE(rc > 0);
    CHECK_THAT(bar.msg, Catch::Matchers::Matches("\thello\n\"world\"!"));
    free_Bar(&bar);

    rc = parse_Bar(&bar, json + rc, strlen(json) - rc);
    REQUIRE(rc > 0);
    CHECK_THAT(bar.msg, Catch::Matchers::Matches("Hello again!"));
    free_Bar(&bar);
}

TEST_CASE("parse incomplete", "[model]") {
    const char *json = R"({
        "msg":"\thello\n\"world\"!"
    )";

    Bar bar = {0};
    REQUIRE(parse_Bar(&bar, json, strlen(json)) == MODEL_PARSE_PARTIAL);
    free_Bar(&bar);

    const char *json_array_partial = R"([
        {"msg":"\thello\n\"world\"!"},
        {"msg":"56")";
    Bar_array bars = nullptr;
    int rc = parse_Bar_array(&bars, json_array_partial, strlen(json_array_partial));
    free_Bar_array(&bars);
    CHECK(rc == MODEL_PARSE_PARTIAL);

    const char *json_array_invalid = R"([
       {"msg":"\thello\n\"world\"!"},
       {"msg":"56"
    ])";
    rc = parse_Bar_array(&bars, json_array_invalid, strlen(json_array_invalid));
    free_Bar_array(&bars);
    CHECK(rc == MODEL_PARSE_INVALID);
}

#define baz_model(XX, ...) \
XX(bar, json, none, bar, __VA_ARGS__) \
XX(ok, model_bool, none, ok, __VA_ARGS__)

#undef MODEL_API
#define MODEL_API static
DECLARE_MODEL(Baz, baz_model)
IMPL_MODEL(Baz, baz_model)

TEST_CASE("test raw json", "[model]") {
    const char *json = "{"
                       "\"bar\":" BAR1 ","
                       "\"ok\": true"
                       "}";
    Baz baz;
    REQUIRE(parse_Baz(&baz, json, strlen(json)) == strlen(json));
    REQUIRE_THAT(remove_space(baz.bar), Equals(remove_space(BAR1)));
    REQUIRE(baz.ok);

    Bar bar;
    REQUIRE(parse_Bar(&bar, baz.bar, strlen(baz.bar)) == strlen(baz.bar));
    checkBar1(bar);
    free_Bar(&bar);
    free_Baz(&baz);
}

#define map_model(XX, ...) \
XX(map, json, map, map, __VA_ARGS__) \
XX(ok, model_bool, none, ok, __VA_ARGS__)

DECLARE_MODEL(ObjMap, map_model)
IMPL_MODEL(ObjMap, map_model)

TEST_CASE("model map test", "[model]") {
    const char *json = "{"
                       "\"map\":" BAR1 ","
                       "\"ok\": true"
                       "}";

    ObjMap o;
    REQUIRE(parse_ObjMap(&o, json, strlen(json)) == strlen(json));
    CHECK(o.ok);
    CHECK_THAT((const char *) model_map_get(&o.map, "num"), Equals("42"));
    CHECK_THAT(
            remove_space((const char *) model_map_get(&o.map, "errors")), Equals(R"(["error1","error2"])"));

    char *j = ObjMap_to_json(&o, 0, NULL);

    std::cout << j << std::endl;
    free(j);

    free_ObjMap(&o);
}

TEST_CASE("model compare", "[model]") {
    Bar b1;
    memset(&b1, 0, sizeof(Bar));
    b1.num = 45;
    b1.isOK = false;
    b1.msg = (char *) "this is bar1";

    Bar b2;
    memset(&b2, 0, sizeof(Bar));
    b2.num = 42;
    b2.isOK = true;
    b2.msg = (char *) "this is bar2";

    CHECK(model_cmp(&b1, &b2, &Bar_META) != 0);

    b1.isOK = true;
    CHECK(model_cmp(&b1, &b2, &Bar_META) != 0);

    b2.num = 45;
    b2.msg = (char *) "this is bar1";
    CHECK(model_cmp(&b1, &b2, &Bar_META) == 0);

    b2.msg = nullptr;
    CHECK(model_cmp(&b1, &b2, &Bar_META) != 0);

    b1.msg = nullptr;
    CHECK(model_cmp(&b1, &b2, &Bar_META) == 0);
}

TEST_CASE("model compare with map", "[model]") {

    ObjMap o1;
    o1.map = {0};
    o1.ok = true;

    ObjMap o2;
    o2.map = {0},
    o2.ok = true;

    CHECK(cmp_ObjMap(&o1, &o2) == 0);

    model_map_set(&o1.map, "key1", (void *) "one");
    CHECK(cmp_ObjMap(&o1, &o2) != 0);

    model_map_set(&o2.map, "key2", (void *) "two");
    CHECK(cmp_ObjMap(&o1, &o2) != 0);

    model_map_set(&o2.map, "key1", (void *) "one");
    model_map_set(&o1.map, "key2", (void *) "two");
    CHECK(cmp_ObjMap(&o1, &o2) == 0);

    model_map_iter it = model_map_iterator(&o1.map);
    while (it != nullptr) {
        it = model_map_it_remove(it);
    }

    it = model_map_iterator(&o2.map);
    while (it != nullptr) {
        it = model_map_it_remove(it);
    }

    free_ObjMap(&o1);
    free_ObjMap(&o2);
}

TEST_CASE("model compare with array", "[model]") {
    const char *bar_json = BAR1;
    Bar bar1, bar2;

    REQUIRE(parse_Bar(&bar1, bar_json, strlen(bar_json)) == strlen(bar_json));
    REQUIRE(parse_Bar(&bar2, bar_json, strlen(bar_json)) == strlen(bar_json));

    CHECK(cmp_Bar(&bar1, &bar2) == 0);


    free((char*)bar1.errors[0]);
    bar1.errors[0] = strdup("changed error");
    CHECK(cmp_Bar(&bar1, &bar2) != 0);

    free_Bar(&bar1);
    free_Bar(&bar2);
}

TEST_CASE("model with null array is null") {
    const char *bar_json = BAR_WITH_NULL_CODES_ARRAY;
    Bar bar;

    REQUIRE(parse_Bar(&bar, bar_json, strlen(bar_json)) == strlen(bar_json));

    CHECK(bar.codes == nullptr);

    free_Bar(&bar);
}

TEST_CASE("model with missing array is null") {
    const char *bar_json = BAR_WITH_MISSING_CODES_ARRAY;
    Bar bar;

    REQUIRE(parse_Bar(&bar, bar_json, strlen(bar_json)) == strlen(bar_json));

    CHECK(bar.codes == nullptr);

    free_Bar(&bar);
}

#define string_map_model(XX, ...) \
XX(tags, model_string, map, tags, __VA_ARGS__)

DECLARE_MODEL(tagged, string_map_model)

IMPL_MODEL(tagged, string_map_model)


TEST_CASE("model with string map", "[model]") {
    const char *json = R"({
        "tags":{
            "num":"42",
            "ok":"true",
            "msg":"hello\nworld!"
        }
    })";

    tagged obj;
    REQUIRE(parse_tagged(&obj, json, strlen(json)) == strlen(json));

    const char *num = (const char *) model_map_get(&obj.tags, "num");
    CHECK_THAT(num, Equals("42"));
    CHECK_THAT((const char *) model_map_get(&obj.tags, "ok"), Equals("true"));
    CHECK_THAT((const char *) model_map_get(&obj.tags, "msg"), Equals("hello\nworld!"));

    char *buf = tagged_to_json(&obj, 0, nullptr);

    printf("%s", buf);
    free_tagged(&obj);
    free(buf);
}

#define objmap_model(XX, ...) \
XX(objects, Bar, map, objects, __VA_ARGS__)

DECLARE_MODEL(MapOfObjects, objmap_model)

IMPL_MODEL(MapOfObjects, objmap_model)

TEST_CASE("map of objects", "[model]") {
    const char *json = "{"
                       "\"objects\":{"
                       "\"bar1\":" BAR1 ","
                       "\"bar2\":" BAR2
                       "}}";

    MapOfObjects m;
    REQUIRE(parse_MapOfObjects(&m, json, strlen(json)) == strlen(json));

    Bar *b1 = static_cast<Bar *>(model_map_get(&m.objects, "bar1"));
    Bar *b2 = static_cast<Bar *>(model_map_get(&m.objects, "bar2"));

    REQUIRE(b1 != nullptr);
    REQUIRE(b2 != nullptr);
    CHECK(b1->num == 42);
    CHECK(!b1->isOK);

    CHECK_THAT(b1->msg, Equals("this is a message"));

    char *js = MapOfObjects_to_json(&m, MODEL_JSON_COMPACT, nullptr);
    std::cout << js << std::endl;
    free(js);

    char small_buf[16];
    ssize_t outlen = MapOfObjects_to_json_r(&m, 0, small_buf, sizeof(small_buf));
    CHECK(outlen == -1);

    char big_buf[1024];
    outlen = MapOfObjects_to_json_r(&m, 0, big_buf, sizeof(big_buf));
    CHECK(outlen > 0);
    std::cout << std::string(big_buf, outlen) << std::endl;

    free_MapOfObjects(&m);
}

#define basket_model(XX, ...) \
XX(json_fruits,json,map, json_fruits,__VA_ARGS__) \
XX(fruits,Fruit,map,fruits,__VA_ARGS__)          \
XX(strings,model_string,map,strings,__VA_ARGS__)

#define fruit_model(XX, ...) \
XX(color,model_string,none,color,__VA_ARGS__) \
XX(count,model_number,none,count,__VA_ARGS__)

DECLARE_MODEL(Fruit, fruit_model)

IMPL_MODEL(Fruit, fruit_model)

DECLARE_MODEL(Basket, basket_model)

IMPL_MODEL(Basket, basket_model)


TEST_CASE("map compare", "[model]") {
    const char *json1 = R"({
  "fruits" : {
    "orange" : {
      "color": "orange",
      "count": 1
    },
    "apple": {
      "color": "red",
      "count": 2
    }
  },
  "json_fruits" : {
    "orange" : {
      "color": "orange",
      "count": 1
    },
    "apple": {
      "color": "red",
      "count": 2
    }
  },
  "strings" : {
     "one": "1",
     "two": "2"
  }
})";

    const char *json2 = R"({
  "json_fruits" : {
    "orange" : {
      "color": "orange",
      "count": 1
    }
  },
  "fruits" : {
    "orange" : {
      "color": "orange",
      "count": 1
    }
  },
  "strings" : {
     "two": "2"
  }
})";

    Basket b1, b2;
    parse_Basket(&b1, json1, strlen(json1));
    parse_Basket(&b2, json2, strlen(json2));

    int rc = cmp_Basket(&b1, &b2);
    CHECK(rc != 0);

    char *apple = (char *) model_map_remove(&b1.json_fruits, "apple");
    free(apple);

    rc = cmp_Basket(&b1, &b2);
    CHECK(rc != 0);

    Fruit *app = (Fruit *) model_map_remove(&b1.fruits, "apple");
    CHECK(app->count == 2);
    CHECK_THAT(app->color, Matches("red"));
    free_Fruit(app);
    free(app);

    char *one = (char *) model_map_remove(&b1.strings, "one");
    CHECK_THAT(one, Matches("1"));
    free(one);

    rc = cmp_Basket(&b1, &b2);
    CHECK(rc == 0);

    free_Basket(&b1);
    free_Basket(&b2);
}

TEST_CASE("parse-json-u-escape", "[model]") {
    const char *json = "{"
                       "\"bar\":{"
                       "\"msg\":\"hello\\u000C\\u0430\\u0431\\u0432\\u0433\\u0434!\""
                       "}"
                       "}";
    Foo foo;
    REQUIRE(parse_Foo(&foo, json, strlen(json)) == strlen(json));

    CHECK_THAT(foo.bar.msg, Catch::Matchers::Equals("hello\u000cабвгд!"));

    size_t json_len;
    char *json_out = Foo_to_json(&foo, 0, &json_len);
    CHECK(json_len == strlen(json_out));
    CHECK_THAT(json_out, Catch::Matchers::ContainsSubstring("\"hello\\u000cабвгд!\""));
    free(json_out);
    free_Foo(&foo);
}

TEST_CASE("parse-bad-json-escapes", "[model]") {
    const char *json[] = {
            // short u escape
            "{"
            "\"bar\":{"
            "\"msg\":\"hello\\u00C\\u0430\\u0431\\u0432\\u0433\\u0434!\""
            "}"
            "}",
            // invalid char in u string
            "{"
            "\"bar\":{"
            "\"msg\":\"hello\\u00OC\\u0430\\u0431\\u0432\\u0433\\u0434!\""
            "}"
            "}",
            // short escape at the end
            "{\"bar\":{"
            "\"msg\":\"hello\\u000C\\u0430\\u0431\\u0432\\u0433\\u\""
            "}}",
            nullptr
        };
    for (int i = 0; json[i] != nullptr; i++) {
        Foo foo;
        CHECK(parse_Foo(&foo, json[i], strlen(json[i])) < 0);
    }
}

TEST_CASE("null to JSON", "[model]") {
    char *json = Foo_to_json(nullptr, 0, nullptr);

    CHECK(json == nullptr);
}

#define LISTS_MODEL(xx, ...) \
xx(fruit, Fruit, list, fruit, __VA_ARGS__)\
xx(errors, model_string, list, errors, __VA_ARGS__)\
xx(codes, model_number, list, codes, __VA_ARGS__)

DECLARE_MODEL(ListsObj, LISTS_MODEL)

IMPL_MODEL(ListsObj, LISTS_MODEL)

TEST_CASE("parse model_list", "[model]") {
    const char *json = R"([
    {
      "color": "orange",
      "count": 1
    },
    {
      "color": "red",
      "count": 2
    }
])";
    model_list list = {0};
    CHECK(parse_Fruit_list(&list, json, strlen(json)) == strlen(json));
    CHECK(model_list_size(&list) == 2);

    auto it = model_list_iterator(&list);
    auto fruit = (Fruit *) model_list_it_element(it);
    CHECK(fruit->count == 1);
    CHECK_THAT(fruit->color, Catch::Matchers::Equals("orange"));
    it = model_list_it_next(it);
    fruit = (Fruit *) model_list_it_element(it);
    CHECK(fruit->count == 2);
    CHECK_THAT(fruit->color, Catch::Matchers::Equals("red"));
    CHECK(model_list_it_next(it) == nullptr);

    auto head = model_list_head(&list);
    fruit = (Fruit *) model_list_pop(&list);
    CHECK(head == fruit);
    CHECK(fruit != model_list_head(&list));
    CHECK(model_list_size(&list) == 1);

    CHECK(fruit->count == 1);
    CHECK_THAT(fruit->color, Catch::Matchers::Equals("orange"));

    free_Fruit_ptr(fruit);
    model_list_clear(&list, (void (*)(void *)) (free_Fruit_ptr));
}

TEST_CASE("list element that fails to parse is released", "[model]") {
    // the elements before the bad one are released with the list, only a leak checker (LSan, leaks) tells about the rest
    const char *json = GENERATE(
            R"({"fruit":[{"color":"red","count":1},{"color":"green","count":"many"}]})",
            R"({"codes":[1,"x"]})",
            R"({"errors":["abc",5]})");
    CAPTURE(json);

    ListsObj o;
    CHECK(parse_ListsObj(&o, json, strlen(json)) < 0);
}

TEST_CASE("array element that fails to parse is released", "[model]") {
    const char *json = GENERATE(
            R"({"errors":["abc",5]})",
            R"({"codes":[1,"x"]})");
    CAPTURE(json);

    Bar bar;
    CHECK(parse_Bar(&bar, json, strlen(json)) < 0);
}

TEST_CASE("array of objects with an element that fails to parse is released", "[model]") {
    const char *json = R"({"bara":[{"msg":"first","num":1},{"msg":"second","num":"many"}]})";

    Foo foo;
    CHECK(parse_Foo(&foo, json, strlen(json)) < 0);
}

TEST_CASE("lists model", "[model]") {
    const char *json = R"(
{
"errors": ["Not Authorized", "Conflict"],
"codes": [401, 409, 413],
"fruit": [
    {
      "color": "orange",
      "count": 1
    },
    {
      "color": "red",
      "count": 2
    }
]
})";

    ListsObj lists;
    CHECK(parse_ListsObj(&lists, json, strlen(json)) == strlen(json));
    CHECK(model_list_size(&lists.codes) == 3);
    CHECK(model_list_size(&lists.errors) == 2);
    CHECK(model_list_size(&lists.fruit) == 2);


    auto it = model_list_iterator(&lists.errors);
    CHECK_THAT((const char *) model_list_it_element(it), Catch::Matchers::Equals("Not Authorized"));
    it = model_list_it_next(it);
    CHECK_THAT((const char *) model_list_it_element(it), Catch::Matchers::Equals("Conflict"));
    CHECK(model_list_it_next(it) == nullptr);

    it = model_list_iterator(&lists.codes);
    CHECK((intptr_t) model_list_it_element(it) == 401);
    it = model_list_it_next(it);
    CHECK((intptr_t) model_list_it_element(it) == 409);
    it = model_list_it_next(it);
    CHECK((intptr_t) model_list_it_element(it) == 413);
    CHECK(model_list_it_next(it) == nullptr);

    it = model_list_iterator(&lists.fruit);
    auto fruit = (Fruit *) model_list_it_element(it);
    CHECK(fruit->count == 1);
    CHECK_THAT(fruit->color, Catch::Matchers::Equals("orange"));
    it = model_list_it_next(it);
    fruit = (Fruit *) model_list_it_element(it);
    CHECK(fruit->count == 2);
    CHECK_THAT(fruit->color, Catch::Matchers::Equals("red"));
    CHECK(model_list_it_next(it) == nullptr);

    char *json_out = ListsObj_to_json(&lists, 0, nullptr);
    printf("%s\n", json_out);

    free_ListsObj(&lists);
    free(json_out);
}

#define DURATION_MODEL(XX, ...) \
XX(timeout, duration, none, timeout, __VA_ARGS__)
DECLARE_MODEL(Duration, DURATION_MODEL)
IMPL_MODEL(Duration, DURATION_MODEL)

TEST_CASE("parse duration", "[model]") {
    using std::make_tuple;
    std::string test_input;
    duration expected_output = 3 * SECOND;
    std::tie( test_input, expected_output ) =
            GENERATE( table<std::string, duration>(
                    {
                        make_tuple(R"({"timeout": "3s"})", (duration)(3 * SECOND)),
                        make_tuple(R"({"timeout": "3m"})", (duration)(3 * MINUTE)),
                        make_tuple(R"({"timeout": "3h"})", 3 * HOUR),
                        make_tuple(R"({"timeout": "3ms"})", 3 * MILLISECOND)
                    })
            );


    Duration d = {0};
    // run the test
    CHECK(parse_Duration(&d, test_input.c_str(), test_input.length()) == test_input.length());
        // capture the input data to go with the outputs.
    CAPTURE(test_input);
        // check it matches the pre-calculated data
    REQUIRE(d.timeout == expected_output);
}

// cstr is the stc string: a plain field is stored in the struct, a ptr/array/list/map element is allocated
typedef cstr **cstr_array;

#define CSTR_MODEL(XX, ...) \
XX(name, cstr, none, name, __VA_ARGS__) \
XX(nick, cstr, ptr, nick, __VA_ARGS__) \
XX(aliases, cstr, array, aliases, __VA_ARGS__) \
XX(roles, cstr, list, roles, __VA_ARGS__) \
XX(labels, cstr, map, labels, __VA_ARGS__)

DECLARE_MODEL(CstrHolder, CSTR_MODEL)
IMPL_MODEL(CstrHolder, CSTR_MODEL)

#define CSTR_HOLDER_JSON \
    R"({"name":"alice","nick":"al","aliases":["a","b"],"roles":["admin","user"],"labels":{"env":"prod"}})"

static std::vector<std::string> cstr_values(const cstr_array arr) {
    std::vector<std::string> values;
    for (int i = 0; arr != nullptr && arr[i] != nullptr; i++) {
        values.emplace_back(cstr_str(arr[i]));
    }
    return values;
}

static std::vector<std::string> cstr_values(model_list *list) {
    std::vector<std::string> values;
    for (auto it = model_list_iterator(list); it != nullptr; it = model_list_it_next(it)) {
        values.emplace_back(cstr_str((const cstr *) model_list_it_element(it)));
    }
    return values;
}

static std::string cstr_holder_json(const CstrHolder &h) {
    size_t len = 0;
    char *json = CstrHolder_to_json(&h, MODEL_JSON_COMPACT, &len);
    REQUIRE(json != nullptr);
    std::string s(json, len);
    free(json);
    return s;
}

TEST_CASE("cstr model round trip", "[model]") {
    const char *json = CSTR_HOLDER_JSON;

    CstrHolder h;
    REQUIRE(parse_CstrHolder(&h, json, strlen(json)) == strlen(json));

    CHECK_THAT(cstr_str(&h.name), Equals("alice"));
    REQUIRE(h.nick != nullptr);
    CHECK_THAT(cstr_str(h.nick), Equals("al"));
    CHECK(cstr_values(h.aliases) == std::vector<std::string>{"a", "b"});
    CHECK(cstr_values(&h.roles) == std::vector<std::string>{"admin", "user"});
    REQUIRE(model_map_size(&h.labels) == 1);
    CHECK_THAT(cstr_str((const cstr *) model_map_get(&h.labels, "env")), Equals("prod"));

    CHECK(cstr_holder_json(h) == json);

    free_CstrHolder(&h);
}

TEST_CASE("cstr model from json object", "[model]") {
    json_object *j = json_tokener_parse(CSTR_HOLDER_JSON);
    REQUIRE(j != nullptr);

    CstrHolder h;
    REQUIRE(CstrHolder_from_json(&h, j) == 0);
    json_object_put(j);

    CHECK_THAT(cstr_str(&h.name), Equals("alice"));
    CHECK(cstr_holder_json(h) == CSTR_HOLDER_JSON);

    free_CstrHolder(&h);
}

TEST_CASE("cstr model missing and null fields", "[model]") {
    const char *json = GENERATE(
            R"({})",
            R"({"name":null,"nick":null,"aliases":null,"roles":null,"labels":null})");
    CAPTURE(json);

    CstrHolder h;
    REQUIRE(parse_CstrHolder(&h, json, strlen(json)) == strlen(json));

    CHECK(cstr_is_empty(&h.name));
    CHECK(h.nick == nullptr);
    CHECK(h.aliases == nullptr);
    CHECK(model_list_size(&h.roles) == 0);
    CHECK(model_map_size(&h.labels) == 0);

    // a plain cstr has no null state: it is written as an empty string, the pointer/collection fields are left out
    CHECK(cstr_holder_json(h) == R"({"name":""})");

    free_CstrHolder(&h);
}

TEST_CASE("cstr model empty collections", "[model]") {
    const char *json = R"({"name":"n","aliases":[],"roles":[],"labels":{}})";

    CstrHolder h;
    REQUIRE(parse_CstrHolder(&h, json, strlen(json)) == strlen(json));

    CHECK(cstr_values(h.aliases).empty());
    CHECK(cstr_values(&h.roles).empty());
    CHECK(model_map_size(&h.labels) == 0);

    free_CstrHolder(&h);
}

TEST_CASE("cstr model string lengths", "[model]") {
    // an stc string keeps up to 22 characters inline and allocates beyond that
    size_t len = GENERATE(0, 1, 22, 23, 24, 300);
    CAPTURE(len);
    std::string value(len, 'x');

    std::string json = R"({"name":")" + value + R"(","nick":")" + value + R"(","aliases":[")" + value +
                       R"("],"roles":[")" + value + R"("],"labels":{"k":")" + value + R"("}})";

    CstrHolder h;
    REQUIRE(parse_CstrHolder(&h, json.c_str(), json.size()) == json.size());

    CHECK(cstr_size(&h.name) == len);
    CHECK(value == cstr_str(&h.name));
    REQUIRE(h.nick != nullptr);
    CHECK(value == cstr_str(h.nick));
    CHECK(cstr_values(h.aliases) == std::vector<std::string>{value});
    CHECK(cstr_values(&h.roles) == std::vector<std::string>{value});
    CHECK(value == cstr_str((const cstr *) model_map_get(&h.labels, "k")));

    CHECK(cstr_holder_json(h) == json);

    free_CstrHolder(&h);
}

TEST_CASE("cstr model escaped characters", "[model]") {
    const char *json = R"({"name":"say \"hi\"\n\ttab \\ slash é ✓","nick":"\u0001 control"})";

    CstrHolder h;
    REQUIRE(parse_CstrHolder(&h, json, strlen(json)) == strlen(json));
    CHECK_THAT(cstr_str(&h.name), Equals("say \"hi\"\n\ttab \\ slash \xc3\xa9 \xe2\x9c\x93"));
    REQUIRE(h.nick != nullptr);
    CHECK_THAT(cstr_str(h.nick), Equals("\x01 control"));

    // what is written must parse back to the same strings
    std::string written = cstr_holder_json(h);
    CstrHolder again;
    REQUIRE(parse_CstrHolder(&again, written.c_str(), written.size()) == written.size());
    CHECK(cmp_CstrHolder(&h, &again) == 0);

    free_CstrHolder(&h);
    free_CstrHolder(&again);
}

TEST_CASE("cstr model rejects values that are not strings", "[model]") {
    const char *json = GENERATE(
            R"({"name":42})",
            R"({"name":true})",
            R"({"name":{"a":"b"}})",
            R"({"nick":1})",
            R"({"aliases":"a"})",
            R"({"aliases":["ok",5]})",
            R"({"roles":"a"})",
            R"({"roles":["ok",{"a":"b"}]})",
            R"({"labels":["a"]})",
            R"({"labels":{"k":false}})",
            // fields parsed before the bad one are released: inline strings, and strings longer than the inline capacity
            R"({"name":"valid","nick":"valid","aliases":["a"],"roles":["a"],"labels":{"k":5}})",
            R"({"name":"a name that is longer than the inline capacity","nick":"a nickname that is longer than the inline capacity","aliases":["an alias that is longer than the inline capacity"],"roles":["a role that is longer than the inline capacity"],"labels":{"k":5}})");
    CAPTURE(json);

    CstrHolder h;
    CHECK(parse_CstrHolder(&h, json, strlen(json)) < 0);
}

TEST_CASE("cstr model compare", "[model]") {
    const char *base = CSTR_HOLDER_JSON;
    CstrHolder a;
    REQUIRE(parse_CstrHolder(&a, base, strlen(base)) == strlen(base));

    SECTION("same content") {
        CstrHolder b;
        REQUIRE(parse_CstrHolder(&b, base, strlen(base)) == strlen(base));
        CHECK(cmp_CstrHolder(&a, &b) == 0);
        CHECK(cmp_CstrHolder(&a, &a) == 0);
        free_CstrHolder(&b);
    }

    SECTION("different content") {
        const char *other = GENERATE(
                R"({"name":"bob","nick":"al","aliases":["a","b"],"roles":["admin","user"],"labels":{"env":"prod"}})",
                R"({"name":"alice","nick":"alf","aliases":["a","b"],"roles":["admin","user"],"labels":{"env":"prod"}})",
                R"({"name":"alice","aliases":["a","b"],"roles":["admin","user"],"labels":{"env":"prod"}})",
                R"({"name":"alice","nick":"al","aliases":["a","c"],"roles":["admin","user"],"labels":{"env":"prod"}})",
                R"({"name":"alice","nick":"al","aliases":["a"],"roles":["admin","user"],"labels":{"env":"prod"}})",
                R"({"name":"alice","nick":"al","aliases":["a","b"],"roles":["admin","guest"],"labels":{"env":"prod"}})",
                R"({"name":"alice","nick":"al","aliases":["a","b"],"roles":["admin"],"labels":{"env":"prod"}})",
                R"({"name":"alice","nick":"al","aliases":["a","b"],"roles":["admin","user"],"labels":{"env":"test"}})",
                R"({"name":"alice","nick":"al","aliases":["a","b"],"roles":["admin","user"],"labels":{"stage":"prod"}})",
                R"({"name":"alice","nick":"al","aliases":["a","b"],"roles":["admin","user"]})");
        CAPTURE(other);

        CstrHolder b;
        REQUIRE(parse_CstrHolder(&b, other, strlen(other)) == strlen(other));
        CHECK(cmp_CstrHolder(&a, &b) != 0);
        CHECK(cmp_CstrHolder(&b, &a) != 0);
        free_CstrHolder(&b);
    }

    free_CstrHolder(&a);
}

TEST_CASE("cstr model array of objects", "[model]") {
    const char *json = R"([{"name":"a","roles":["x"]},{"name":"b","aliases":["y","z"]}])";

    CstrHolder_array holders = nullptr;
    REQUIRE(parse_CstrHolder_array(&holders, json, strlen(json)) == strlen(json));
    REQUIRE(holders != nullptr);
    REQUIRE(holders[0] != nullptr);
    REQUIRE(holders[1] != nullptr);
    CHECK(holders[2] == nullptr);

    CHECK_THAT(cstr_str(&holders[0]->name), Equals("a"));
    CHECK(cstr_values(&holders[0]->roles) == std::vector<std::string>{"x"});
    CHECK_THAT(cstr_str(&holders[1]->name), Equals("b"));
    CHECK(cstr_values(holders[1]->aliases) == std::vector<std::string>{"y", "z"});

    free_CstrHolder_array(&holders);
    CHECK(holders == nullptr);
}

TEST_CASE("cstr as a model type", "[model]") {
    const type_meta *meta = get_cstr_meta();
    REQUIRE(meta != nullptr);
    CHECK_THAT(meta->name, Equals("cstr"));
    CHECK(meta->size == sizeof(cstr));

    cstr *s = (cstr *) model_alloc(meta);
    REQUIRE(s != nullptr);

    const char *json = R"("a string that is longer than the inline capacity")";
    REQUIRE(model_parse(s, json, strlen(json), meta) == strlen(json));
    CHECK_THAT(cstr_str(s), Equals("a string that is longer than the inline capacity"));

    size_t len = 0;
    char *out = model_to_json(s, meta, MODEL_JSON_COMPACT, &len);
    REQUIRE(out != nullptr);
    CHECK(std::string(out, len) == json);
    free(out);

    cstr *same = (cstr *) model_alloc(meta);
    REQUIRE(model_parse(same, json, strlen(json), meta) == strlen(json));
    CHECK(model_cmp(s, same, meta) == 0);
    cstr_assign(same, "other");
    CHECK(model_cmp(s, same, meta) != 0);

    const char *not_a_string = "12";
    cstr *bad = (cstr *) model_alloc(meta);
    CHECK(model_parse(bad, not_a_string, strlen(not_a_string), meta) < 0);

    model_free(s, meta);
    model_free(same, meta);
    free(s);
    free(same);
    free(bad);
}
