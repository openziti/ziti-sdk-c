set(ZITI_HEADER_FILES
        ${PROJECT_SOURCE_DIR}/includes/ziti/errors.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/error_defs.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/enums.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti_src.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti_events.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/ziti_buffer.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/socket.h
        ${PROJECT_SOURCE_DIR}/includes/ziti/model_map.h
        )

SET(ZITI_SRC_FILES
        utils.c
        ziti.c
        config.c
        errors.c
        ziti_enroll.c
        jwt.c
        ziti_ctrl.c
        model_support.c
        internal_model.c
        connect.c
        channel.c
        message.c
        buffer.c
        ziti_src.c
        metrics.c
        posture.c
        auth_queries.c
        conn_bridge.c
        ziti-socket.c
        pool.c
        model_map.c
        )

SET(ZITI_INCLUDE_DIRS
    PUBLIC ../includes
    PRIVATE ../inc_internal
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${uv-mbed_SOURCE_DIR}/src
)

add_library(ziti     STATIC ${ZITI_SRC_FILES} ${ZITI_HEADER_FILES} )
add_library(ziti_dll SHARED ${ZITI_SRC_FILES} ${ZITI_HEADER_FILES} )
set_target_properties(ziti_dll PROPERTIES OUTPUT_NAME "ziti")

# disable using the 'lib' prefix when crosscompiling
if (WIN32)
set_target_properties(ziti ziti_dll PROPERTIES PREFIX "")
#without this libsodioum was complaining:
endif()

# when building on windows an "import library" is generated which is overwriting the
# static library (ziti.lib) (google/see /IMPLIB (Name Import Library))
# work around discovered at stack overflow:
#     https://stackoverflow.com/questions/34575066/how-to-prevent-cmake-from-issuing-implib
#
# I chose to set the suffix and not the prefix
# set_target_properties(ziti_dll PROPERTIES IMPORT_PREFIX "import-lib-")
set_target_properties(ziti_dll PROPERTIES IMPORT_SUFFIX ".imp.lib")

set_property(TARGET ziti ziti_dll PROPERTY C_STANDARD 11)

target_sources(ziti     PRIVATE ${ZITI_PRIVATE_SRC_FILES})
target_sources(ziti_dll PRIVATE ${ZITI_PRIVATE_SRC_FILES})

target_link_libraries(ziti     PUBLIC uv_mbed sodium)
target_link_libraries(ziti_dll PUBLIC uv_mbed sodium)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_link_libraries(ziti PUBLIC atomic)
    target_link_libraries(ziti_dll PUBLIC atomic)
endif()

if (NOT WIN32)
    target_link_libraries(ziti PUBLIC m)
    target_link_libraries(ziti_dll PUBLIC m)
endif ()

target_include_directories(ziti     ${ZITI_INCLUDE_DIRS})
target_include_directories(ziti_dll ${ZITI_INCLUDE_DIRS})
set_target_properties(ziti_dll PROPERTIES OUTPUT_NAME "ziti")

set(ziti_compile_defs
        BUILD_DATE=${BUILD_DATE}
        ZITI_VERSION=${PROJECT_VERSION}
        ZITI_BRANCH=${GIT_BRANCH}
        ZITI_COMMIT=${GIT_COMMIT_HASH}
        PRIVATE ZITI_LOG_MODULE="${PROJECT_NAME}"
        )

if (ZITI_BUILDNUM)
    list(APPEND ziti_compile_defs
            ZITI_BUILDNUM=${ZITI_BUILDNUM}
            )
endif()

target_compile_definitions(ziti PUBLIC
        ${ziti_compile_defs}
)

target_compile_definitions(ziti_dll PUBLIC
        ${ziti_compile_defs}
        INTERFACE USING_ZITI_SHARED=1
        PRIVATE BUILDING_ZITI_SHARED=1
)

if (WIN32)
    # on windows GDI defines ERROR which conflicts with the SDK declaration of DEBUG_LEVELS in utils.h
    target_compile_definitions(ziti     PUBLIC NOGDI _CRT_NONSTDC_NO_DEPRECATE)
    target_compile_definitions(ziti_dll PUBLIC NOGDI _CRT_NONSTDC_NO_DEPRECATE)

    target_link_libraries(ziti     PUBLIC crypt32 netapi32)
    target_link_libraries(ziti_dll PUBLIC crypt32 netapi32)
endif()

set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(prefix ${CMAKE_INSTALL_PREFIX})

configure_file(${PROJECT_SOURCE_DIR}/ziti.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc @ONLY)

set(CMAKE_INSTALL_DOCDIR share/doc)

install(TARGETS ziti ziti_dll
        COMPONENT ziti-sdk
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../includes/
        COMPONENT ziti-sdk
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(ziti_DEPS_DIR ${CMAKE_BINARY_DIR}/_deps)
if (NOT USE_OPENSSL)
    install(FILES ${ziti_DEPS_DIR}/mbedtls-src/LICENSE
            COMPONENT ziti-sdk
            DESTINATION ${CMAKE_INSTALL_DOCDIR}/mbedtls)
endif ()
if (NOT HAVE_LIBUV)
    install(FILES ${ziti_DEPS_DIR}/libuv-src/LICENSE
            COMPONENT ziti-sdk
            DESTINATION ${CMAKE_INSTALL_DOCDIR}/libuv)
endif ()
install(FILES ${uv-mbed_SOURCE_DIR}/LICENSE
        COMPONENT ziti-sdk
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/uv_mbed)
install(FILES ${ziti_DEPS_DIR}/uv_link-src/README.md
        COMPONENT ziti-sdk
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/uv_link_t)
install(FILES ${ziti_DEPS_DIR}/http_parser-src/LICENSE-MIT
        COMPONENT ziti-sdk
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/http-parser)

if (NOT WIN32)
    # no license file windows pre-built bundle
    if (NOT HAVE_LIBSODIUM)
        install(FILES ${CMAKE_BINARY_DIR}/_deps/libsodium-src/LICENSE
                COMPONENT ziti-sdk
                DESTINATION ${CMAKE_INSTALL_DOCDIR}/libsodium)
    endif ()
endif ()

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ziti.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

