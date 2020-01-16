add_library(ziti STATIC
        utils.c strutils.h
        ziti.c
        config.c
        errors.c
        ziti_ctrl.c
        model.c
        connect.c
        channel.c
        message.c
        buffer.c
        ${ZITI_HEADER_FILES}
        )

set_property(TARGET ziti PROPERTY C_STANDARD 11)

target_sources(ziti
        PRIVATE ${PROJECT_SOURCE_DIR}/deps/http-parser/http_parser.c)

target_link_libraries(ziti
    PUBLIC uv_mbed
)
        
if (NOT WIN32)
    target_link_libraries(ziti
        PUBLIC m
        )
endif()

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
    target_compile_definitions(ziti PUBLIC NOGDI _CRT_NONSTDC_NO_DEPRECATE)
    target_link_libraries(ziti PUBLIC crypt32)
endif()

set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(prefix ${CMAKE_INSTALL_PREFIX})

configure_file(${PROJECT_SOURCE_DIR}/ziti.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc @ONLY)

set(CMAKE_INSTALL_DOCDIR share/doc)

install(TARGETS ziti
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

install(DIRECTORY ${CMAKE_SOURCE_DIR}/includes/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${CMAKE_SOURCE_DIR}/deps/http-parser/LICENSE-MIT DESTINATION ${CMAKE_INSTALL_DOCDIR}/http-parser)
install(FILES ${CMAKE_SOURCE_DIR}/deps/mjson/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/mjson)
install(FILES ${CMAKE_SOURCE_DIR}/deps/uv-mbed/deps/mbedtls/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/mbedtls)
install(FILES ${CMAKE_SOURCE_DIR}/deps/uv-mbed/deps/uv_link_t/README.md DESTINATION ${CMAKE_INSTALL_DOCDIR}/uv_link_t)
install(FILES ${CMAKE_SOURCE_DIR}/deps/uv-mbed/deps/mbedtls/crypto/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/mbedtls/crypto)
install(FILES ${CMAKE_SOURCE_DIR}/deps/uv-mbed/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/uv_mbed)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

