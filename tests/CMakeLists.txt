cmake_policy(SET CMP0134 NEW) # allow find_package to use the CMAKE_IMPORT_FILE_VERSION variable
find_package(Catch2 CONFIG)
if (NOT Catch2_FOUND)
    message(NOTICE "Catch2 not found or is not compatible.")
    return()
endif ()
message("catch2 is ${Catch2_CONFIG}")

add_executable(all_tests
        test_ziti_model.cpp
        test_jwt.cpp
        model_tests.cpp
        test_metrics.cpp
        enum_tests.cpp
        collections_tests.cpp
        buffer_tests.cpp
        pool_tests.cpp
        catch2_includes.hpp
        ziti_src_tests.cpp
        message_tests.cpp
        util_tests.cpp)

if (WIN32)
    set_property(TARGET all_tests PROPERTY CXX_STANDARD 20)
else ()
    set_property(TARGET all_tests PROPERTY CXX_STANDARD 14)
endif ()

target_compile_definitions(all_tests
        PRIVATE ZITI_TEST_DIR=${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(all_tests
        PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal
        PRIVATE ${ziti-sdk_SOURCE_DIR}/library
)

target_link_libraries(all_tests
        PRIVATE ziti
        PRIVATE Catch2::Catch2 Catch2::Catch2WithMain)

add_executable(zitilib-tests zitilib-tests.cpp)
target_link_libraries(zitilib-tests
        PRIVATE ziti
        PRIVATE Catch2::Catch2WithMain)

include(CTest)
add_test(quick_tests all_tests -d yes "~[integ]~[metrics]")

add_test(zitilib_tests zitilib-tests -d yes)

add_subdirectory(integ)

