
include(${ziti-deps_BINARY_DIR}/Catch2/${CMAKE_INSTALL_LIBDIR}/cmake/Catch2/Catch.cmake)
include(${ziti-deps_BINARY_DIR}/Catch2/${CMAKE_INSTALL_LIBDIR}/cmake/Catch2/ParseAndAddCatchTests.cmake)

add_executable(all_tests
        all_tests.cpp
        test_keys.cpp
        test_model.cpp)
set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)

target_include_directories(all_tests PRIVATE ${ziti-deps_BINARY_DIR}/Catch2/include)
target_link_libraries(all_tests
        PRIVATE ziti)

set(TEST_DATA
        test_key.pem
        softhsm2.conf
        init-test-data.sh
        find-softhsm-lib.sh)

add_custom_target(gen-test-data
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/init-test-data.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_dependencies(all_tests gen-test-data)

file(COPY ${TEST_DATA}
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

include(CTest)
ParseAndAddCatchTests(all_tests)

