project(ziti-prox-c)

add_executable(ziti-prox-c proxy.c)

if(WIN32)
    target_include_directories(ziti-prox-c PRIVATE win32/include)
    target_sources(ziti-prox-c PRIVATE win32/src/getopt.c)
endif()

target_link_libraries(ziti-prox-c PUBLIC ziti subcommand)
target_include_directories(ziti-prox-c PRIVATE ${ziti-sdk_SOURCE_DIR}/inc_internal)

set(ZITI_EXECUTABLE_NAME "ziti-prox-c-${ZITI_VERSION}-${CPACK_SYSTEM_NAME}.${archive_sfx}")
if (UNIX)
    add_custom_target(ziti-prox-c-pack
            BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${ZITI_EXECUTABLE_NAME}
            DEPENDS ziti-prox-c
            COMMAND tar zcf ${ZITI_EXECUTABLE_NAME} ziti-prox-c${CMAKE_EXECUTABLE_SUFFIX}
            )
else()
    if(EXISTS "${ZITI_EXECUTABLE_NAME}")
        add_custom_target(ziti-prox-c-pack
                BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${ZITI_EXECUTABLE_NAME}
                DEPENDS ziti-prox-c
                COMMAND zip ${ZITI_EXECUTABLE_NAME} ziti-prox-c${CMAKE_EXECUTABLE_SUFFIX}
                )
    else()
        if(EXISTS "${CMAKE_BUILD_TYPE}/${ZITI_EXECUTABLE_NAME}")
        add_custom_target(ziti-prox-c-pack
                BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${ZITI_EXECUTABLE_NAME}
                DEPENDS ziti-prox-c
                COMMAND ${CMAKE_BUILD_TYPE}/zip ${ZITI_EXECUTABLE_NAME} ziti-prox-c${CMAKE_EXECUTABLE_SUFFIX}
                )
        else()
            MESSAGE("NO EXECUTABLE EXISTS: ${ZITI_EXECUTABLE_NAME}")
        endif()
    endif()
endif()

#add_dependencies(publish ZITI_EXECUTABLE_NAME)
PUBCOMP(ziti-prox-c)