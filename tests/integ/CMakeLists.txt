
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

add_executable(echo-server echo-server.c)
target_link_libraries(echo-server PRIVATE ziti)

add_executable(integ-tests
        main.cpp
        legacy-auth.cpp
        oidc-tests.cpp
        ctrl_tests.cpp
        enroll_tests.cpp
        enroll_token_tests.cpp
        enroll_mode_tests.cpp
        connect_tests.cpp
        zitilib_tests.cpp
        zl_connect_tests.cpp
)
target_include_directories(integ-tests
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include
        PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal)
target_link_libraries(integ-tests
        PRIVATE ziti
        PRIVATE Catch2::Catch2WithMain
)

set_property(TARGET integ-tests PROPERTY CXX_STANDARD 23)
if (MINGW)
    target_link_options(integ-tests PRIVATE -static-libgcc)
endif ()

find_program(Python3_EXECUTABLE NAMES python3 python)
if (Python3_EXECUTABLE)
    message(NOTICE "python3: ${Python3_EXECUTABLE}")
    set(INTEG_VENV_DIR "${CMAKE_CURRENT_BINARY_DIR}/venv")
    if (NOT EXISTS "${INTEG_VENV_DIR}")
        message(NOTICE "creating pytest venv at ${INTEG_VENV_DIR}")
        execute_process(
                COMMAND ${Python3_EXECUTABLE} -m venv venv
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                RESULT_VARIABLE _venv_rc
                ERROR_VARIABLE _venv_err
                OUTPUT_VARIABLE _venv_out
        )
        message(NOTICE "venv output: ${_venv_out}")
        message(NOTICE "venv error: ${_venv_err}")
        message(NOTICE "venv return code: ${_venv_rc}")
    endif ()
    find_program(PIP_EXECUTABLE NAMES pip3 pip PATHS "${INTEG_VENV_DIR}/bin" "${INTEG_VENV_DIR}/Scripts" NO_DEFAULT_PATH)
    message(NOTICE "pip: ${PIP_EXECUTABLE}")
    execute_process(
            COMMAND "${PIP_EXECUTABLE}" install -U -r "${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE _pip_rc
            ERROR_VARIABLE _pip_err
            OUTPUT_VARIABLE _pip_out
    )
    message(NOTICE "pip output: ${_pip_out}")
    message(NOTICE "pip error: ${_pip_err}")
    message(NOTICE "pip return code: ${_pip_rc}")
    if (NOT _pip_rc EQUAL 0)
        message(WARNING "pip install pytest failed: pytest-based integration testing is not enabled")
    endif ()

    find_program(PYTEST_EXECUTABLE NAMES pytest PATHS "${INTEG_VENV_DIR}/bin" "${INTEG_VENV_DIR}/Scripts" NO_DEFAULT_PATH)
    message(NOTICE "pytest: ${PYTEST_EXECUTABLE}")
    if (EXISTS "${PYTEST_EXECUTABLE}")
        set(INTEG_TEST_DATA_DIR "${CMAKE_CURRENT_BINARY_DIR}/testdata")

        file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
        file(GLOB test_scripts RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.py")
        foreach (f ${test_scripts})
            message(NOTICE "found test script: ${f}")
            configure_file(${f} "${CMAKE_CURRENT_BINARY_DIR}/tests/${f}" COPYONLY)
        endforeach ()

        file(MAKE_DIRECTORY ${INTEG_TEST_DATA_DIR})
        configure_file(env.in env.in @ONLY)
        file(GENERATE OUTPUT "${INTEG_TEST_DATA_DIR}/env.$<CONFIG>"
                INPUT ${CMAKE_CURRENT_BINARY_DIR}/env.in)
        add_test(NAME pytest-integ
                COMMAND ${PYTEST_EXECUTABLE} -v --setup-show
                --basetemp ${INTEG_TEST_DATA_DIR}/temp
                --envfile ${INTEG_TEST_DATA_DIR}/env.$<CONFIG>
                --junitxml=${INTEG_TEST_DATA_DIR}/TEST-integration-tests.xml
                "${CMAKE_CURRENT_BINARY_DIR}/tests"
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
        set_tests_properties(pytest-integ PROPERTIES
                TIMEOUT 600
                DEPENDS "sample_enroll;integ-tests;echo-server"
        )
    endif ()
else ()
    message(WARNING "python3 not found: pytest-based integration testing is not enabled")
endif ()

