project(ziti-prox-c)

add_executable(ziti-prox-c proxy.c)

if(WIN32)
    target_include_directories(ziti-prox-c PRIVATE win32/include)
    target_sources(ziti-prox-c PRIVATE win32/src/getopt.c)
endif()

target_link_libraries(ziti-prox-c PUBLIC ziti subcommand)
target_include_directories(ziti-prox-c PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal)

add_custom_target(ziti-prox-c-${ZITI_VERSION}-${CMAKE_SYSTEM_NAME}.tar.gz ALL
        DEPENDS ziti-prox-c
        COMMAND tar zcf ziti-prox-c-${ZITI_VERSION}-${CMAKE_SYSTEM_NAME}.tar.gz ziti-prox-c${CMAKE_EXECUTABLE_SUFFIX}
        )

#add_dependencies(package ziti-prox-c-pack)

PUBCOMP(ziti-prox-c)