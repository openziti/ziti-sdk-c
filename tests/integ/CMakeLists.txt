
find_program(EXPECTOR NAMES expect)
if (NOT EXPECTOR)
    message(WARNING "expect not found: integration testing is not enabled")
    return()
endif ()

execute_process(COMMAND ${EXPECTOR} -v)

find_program(GOLANG_EXE NAMES go REQUIRED)

set(test_client_json ${CMAKE_CURRENT_BINARY_DIR}/test-client.json)
set(test_server_json ${CMAKE_CURRENT_BINARY_DIR}/test-server.json)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/test-data.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/include/test-data.h
        @ONLY
)

add_executable(integ-tests
        main.cpp)
target_include_directories(integ-tests
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include
        PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal)
target_link_libraries(integ-tests
        PRIVATE ziti
        PRIVATE Catch2::Catch2WithMain
)

if (WIN32)
    set_property(TARGET integ-tests PROPERTY CXX_STANDARD 20)
else ()
    set_property(TARGET integ-tests PROPERTY CXX_STANDARD 14)
endif ()

set(ZITI_CLI_VER "v0.32.2" CACHE STRING "ziti version for integration tests")
add_custom_target(ziti-cli ALL
        COMMAND ${CMAKE_COMMAND} -E env GOBIN=${CMAKE_CURRENT_BINARY_DIR}
        ${GOLANG_EXE} install github.com/openziti/ziti/ziti@${ZITI_CLI_VER}
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/ziti
)

set(ZITI_CLI ${CMAKE_CURRENT_BINARY_DIR}/ziti)

set(qs_home ${CMAKE_CURRENT_BINARY_DIR}/qs-home)
add_test(NAME quickstart-bootstrap
        COMMAND ${EXPECTOR} ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap.exp
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND_EXPAND_LISTS
)
set_tests_properties(quickstart-bootstrap PROPERTIES
        FIXTURES_SETUP QS
        ENVIRONMENT "ZITI_CLI=${ZITI_CLI};ZITI_CONFIG_DIR=${qs_home};QUICKSTART_HOME=${qs_home};ENROLLER=$<TARGET_FILE:sample_enroll>"
        DEPENDS "sample_enroll;ziti-cli"
)

add_test(NAME quickstart-test
        COMMAND ${EXPECTOR} ${CMAKE_CURRENT_SOURCE_DIR}/integ-test.exp
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(quickstart-test PROPERTIES
        FIXTURES_REQUIRED QS
        DEPENDS "integ-tests"
        ENVIRONMENT "ZITI_CLI=${ZITI_CLI};ZITI_CONFIG_DIR=${qs_home};QUICKSTART_HOME=${qs_home};TEST_EXE=$<TARGET_FILE:integ-tests>"
)

add_test(NAME quickstart-cleanup
        COMMAND rm -rf ${qs_home}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(quickstart-cleanup PROPERTIES FIXTURES_CLEANUP QS)

