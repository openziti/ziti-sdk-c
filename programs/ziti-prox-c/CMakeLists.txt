
project(ziti-prox-c
        VERSION ${CMAKE_PROJECT_VERSION}
        LANGUAGES C CXX
        )
add_executable(ziti-prox-c proxy.c)

if(WIN32)
    target_include_directories(ziti-prox-c PRIVATE win32/include)
    target_sources(ziti-prox-c PRIVATE win32/src/getopt.c)
endif()

target_link_libraries(ziti-prox-c PUBLIC ziti subcommand)
target_include_directories(ziti-prox-c PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal)

set(ZITI_ARCHIVE_NAME "ziti-prox-c-${PROJECT_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx}")
set(ZITI_EXECUTABLE_NAME "ziti-prox-c${CMAKE_EXECUTABLE_SUFFIX}")
if (UNIX)
    add_custom_target(ziti-prox-c-pack
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${ZITI_ARCHIVE_NAME}
        DEPENDS ziti-prox-c
        COMMAND tar zcf ${ZITI_ARCHIVE_NAME} ${ZITI_EXECUTABLE_NAME}
    )
else()
    add_custom_target(ziti-prox-c-pack
        BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/${ZITI_ARCHIVE_NAME}"
            DEPENDS ziti-prox-c
            COMMAND zip "${ZITI_ARCHIVE_NAME}" "${PROJECT_BINARY_DIR}/${CMAKE_BUILD_TYPE_INIT}/${ZITI_EXECUTABLE_NAME}"
            )
endif()
