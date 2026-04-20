
find_program(ZITI_CLI NAMES ziti)
if (NOT ZITI_CLI)
    message(WARNING "ziti cli was not found: integration testing is not possible")
    return()
endif ()
message(NOTICE "ziti cli: ${ZITI_CLI}")

set(qs_home ${CMAKE_CURRENT_BINARY_DIR}/qs-home)
set(test_client_jwt ${qs_home}/test-client.jwt)
set(test_server_jwt ${qs_home}/test-server.jwt)
set(test_client_json ${qs_home}/test-client.json)
set(test_server_json ${qs_home}/test-server.json)
set(test_service test-service)
set(test_jwt_signer_key ${qs_home}/test-jwt-signer.key)
set(test_jwt_signer_kid ${qs_home}/test-jwt-signer.kid)
set(test_keycloak_available ${qs_home}/keycloak-available)
set(test_keycloak_host ${qs_home}/keycloak-host)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/test-data.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/include/test-data.h
        @ONLY
)

add_executable(integ-tests
        main.cpp
        legacy-auth.cpp
        oidc-tests.cpp
        ctrl_tests.cpp
        enroll_tests.cpp
        enroll_token_tests.cpp
        enroll_mode_tests.cpp
)
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

find_program(Python3_EXECUTABLE NAMES python3 python)
if (Python3_EXECUTABLE)
    set(INTEG_VENV_DIR "${CMAKE_CURRENT_BINARY_DIR}/venv")
    if (NOT EXISTS "${INTEG_VENV_DIR}")
        message(NOTICE "creating pytest venv at ${INTEG_VENV_DIR}")
        execute_process(
                COMMAND ${Python3_EXECUTABLE} -m venv "${INTEG_VENV_DIR}"
                RESULT_VARIABLE _venv_rc
        )
    endif ()
    execute_process(
            COMMAND "${INTEG_VENV_DIR}/bin/pip" install -U -r "${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE _pip_rc
    )
    if (NOT _pip_rc EQUAL 0)
        message(WARNING "pip install pytest failed: pytest-based integration testing is not enabled")
    endif ()

    if (EXISTS "${INTEG_VENV_DIR}/bin/pytest")
        set(PYTEST "${INTEG_VENV_DIR}/bin/pytest")
        set(INTEG_TEST_DATA_DIR "${CMAKE_CURRENT_BINARY_DIR}/testdata")
        file(MAKE_DIRECTORY ${INTEG_TEST_DATA_DIR})

        message(NOTICE "pytest: ${PYTEST}")
        configure_file(env.in env.in @ONLY)
        file(GENERATE OUTPUT "${INTEG_TEST_DATA_DIR}/.env.$<CONFIG>"
                INPUT ${CMAKE_CURRENT_BINARY_DIR}/env.in)
        add_test(NAME pytest-integ
                COMMAND ${PYTEST} -v ${CMAKE_CURRENT_SOURCE_DIR}/ --envfile ${INTEG_TEST_DATA_DIR}/.env.$<CONFIG>
                --junitxml=${INTEG_TEST_DATA_DIR}/pytest-integ-results.xml
                WORKING_DIRECTORY ${INTEG_TEST_DATA_DIR}
        )
        set_tests_properties(pytest-integ PROPERTIES
                TIMEOUT 600
                DEPENDS "sample_enroll;integ-tests"
        )
    endif ()
else ()
    message(WARNING "python3 not found: pytest-based integration testing is not enabled")
endif ()

