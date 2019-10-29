add_library(ziti STATIC
        utils.c strutils.h
        ziti.c
        zt_auth.c
        config.c
        tls.c
        errors.c
        controller.c
        model.c
        connect.c
        channel.c
        message.c
        buffer.c
        p11/mbed_p11.c
        p11/p11_ecdsa.c
        p11/p11_rsa.c
        )

target_sources(ziti
        PRIVATE ${PROJECT_SOURCE_DIR}/deps/http-parser/http_parser.c)

target_link_libraries(ziti
        PUBLIC uv_mbed
        PUBLIC m
        )

target_include_directories(ziti
        PUBLIC ../includes
        PRIVATE ../inc_internal
        PRIVATE ${PROJECT_BINARY_DIR}/include
        PRIVATE ${PROJECT_SOURCE_DIR}/deps/mjson
        PUBLIC ${PROJECT_SOURCE_DIR}/deps/http-parser)

target_compile_definitions(ziti PUBLIC
        ZITI_BUILDNUM=${ZITI_BUILDNUM}
        BUILD_DATE=${BUILD_DATE}
        ZITI_VERSION=${PROJECT_VERSION}
        ZITI_BRANCH=${GIT_BRANCH}
        ZITI_COMMIT=${GIT_COMMIT_HASH})

if (WIN32)
    # on windows GDI defines ERROR which conflicts with the SDK declaration of DEBUG_LEVELS in utils.h
    target_compile_definitions(ziti PUBLIC NOGDI)
    target_link_libraries(ziti PUBLIC crypt32)
endif()

set_property(TARGET ziti PROPERTY C_STANDARD 11)

set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(prefix ${CMAKE_INSTALL_PREFIX})

configure_file(${PROJECT_SOURCE_DIR}/ziti.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc @ONLY)

set(CMAKE_INSTALL_DOCDIR share/doc)

install(TARGETS ziti
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION lib)

message("DIRECTORY ${CMAKE_SOURCE_DIR}/includes/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}")
install(DIRECTORY ${CMAKE_SOURCE_DIR}/includes/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${CMAKE_SOURCE_DIR}/deps/http-parser/LICENSE-MIT DESTINATION ${CMAKE_INSTALL_DOCDIR}/http-parser)
install(FILES ${CMAKE_SOURCE_DIR}/deps/mjson/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/mjson)
install(FILES ${CMAKE_SOURCE_DIR}/deps/uv-mbed/mbedtls/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/mbedtls)
install(FILES ${CMAKE_SOURCE_DIR}/deps/uv-mbed/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/uv_mbed)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

