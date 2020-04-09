
add_executable(all_tests
        all_tests.cpp
        test_ziti_model.cpp
        ctrl_tests.cpp
        test_jwt.cpp
        pkcs7_tests.cpp
        model_tests.cpp
        )
set_property(TARGET all_tests PROPERTY CXX_STANDARD 20)

target_include_directories(all_tests
        PRIVATE ${ziti-deps_BINARY_DIR}/Catch2/include
        PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal)

target_link_libraries(all_tests
        PRIVATE ziti)

include(CTest)
add_test(quick_tests all_tests "exclude:[integ]")

