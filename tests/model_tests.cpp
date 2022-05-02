/*
Copyright (c) 2020 Netfoundry, Inc.

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

#include <cstring>
#include "catch2/catch.hpp"

#include <ziti/model_support.h>
#include <iostream>

#define BAR_MODEL(xx, ...)\
xx(num, int, none, num, __VA_ARGS__)\
xx(nump, int, ptr, nump, __VA_ARGS__) \
xx(isOK, bool, none, ok, __VA_ARGS__)\
xx(msg, string, none, msg, __VA_ARGS__)\
xx(ts, timestamp, ptr, time, __VA_ARGS__)\
xx(errors, string, array, errors, __VA_ARGS__)\
xx(codes, int, array, codes, __VA_ARGS__)

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
\"codes\": [401, 403] \
}"

#define BAR_WITH_NULL_CODES_ARRAY "{\
\"num\":42,\
\"ok\": false,\
\"time\": \"2020-07-20T14:14:14.666666Z\",\
\"msg\":\"this is a message\",\
\"errors\": [\"error1\", \"error2\"], \
\"codes\": null \
}"

#define BAR_WITH_MISSING_CODES_ARRAY "{\
\"num\":42,\
\"ok\": false,\
\"time\": \"2020-07-20T14:14:14.666666Z\",\
\"msg\":\"this is a message\",\
\"errors\": [\"error1\", \"error2\"] \
}"

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

    char *json = Bar_to_json(&bar, 0, nullptr);
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
    CHECK_THAT(bars[0]->msg, Catch::Matches("\thello\n\"world\"!"));
    CHECK_THAT(bars[1]->msg, Catch::Matches("Hello again!"));
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
    CHECK_THAT(bar.msg, Catch::Matches("\thello\n\"world\"!"));
    free_Bar(&bar);

    rc = parse_Bar(&bar, json + rc, strlen(json) - rc);
    REQUIRE(rc > 0);
    CHECK_THAT(bar.msg, Catch::Matches("Hello again!"));
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
XX(ok, bool, none, ok, __VA_ARGS__)

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
    REQUIRE_THAT(baz.bar, Equals(BAR1));
    REQUIRE(baz.ok);

    Bar bar;
    REQUIRE(parse_Bar(&bar, baz.bar, strlen(baz.bar)) == strlen(baz.bar));
    checkBar1(bar);
    free_Bar(&bar);
    free_Baz(&baz);
}

#define map_model(XX, ...) \
XX(map, model_map, none, map, __VA_ARGS__) \
XX(ok, bool, none, ok, __VA_ARGS__)

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
    CHECK_THAT((const char *) model_map_get(&o.map, "errors"), Equals(R"(["error1", "error2"])"));

    char *j = ObjMap_to_json(&o, 0, NULL);

    std::cout << j << std::endl;
    free(j);

    model_map_clear(&o.map, nullptr);
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


    free(bar1.errors[0]);
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
XX(tags, string, map, tags, __VA_ARGS__)

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
XX(strings,string,map,strings,__VA_ARGS__)

#define fruit_model(XX, ...) \
XX(color,string,none,color,__VA_ARGS__) \
XX(count,int,none,count,__VA_ARGS__)

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
    CHECK_THAT(json_out, Catch::Matchers::Contains("\"hello\\u000cабвгд!\""));
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