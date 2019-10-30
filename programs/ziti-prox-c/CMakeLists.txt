project(ziti-prox-c)

add_executable(ziti-prox-c proxy.c)

if(WIN32)
    target_include_directories(ziti-prox-c PRIVATE win32/include)
    target_sources(ziti-prox-c PRIVATE win32/src/getopt.c)
endif()

target_link_libraries(ziti-prox-c PUBLIC ziti subcommand)
target_include_directories(ziti-prox-c PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal)

if (UNIX)
    add_custom_target(ziti-prox-c-pack
            BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/ziti-prox-c-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx}
            DEPENDS ziti-prox-c
            COMMAND tar zcf ziti-prox-c-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx} ziti-prox-c${CMAKE_EXECUTABLE_SUFFIX}
            )
else()
    add_custom_target(ziti-prox-c-pack
            BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/ziti-prox-c-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx}
            DEPENDS ziti-prox-c
            COMMAND zip ziti-prox-c-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx} ziti-prox-c${CMAKE_EXECUTABLE_SUFFIX}
            )
endif()

#add_dependencies(publish ziti-prox-c-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx})
PUBCOMP(ziti-prox-c)