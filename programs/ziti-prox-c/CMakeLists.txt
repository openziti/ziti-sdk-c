
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

set(ZITI_ARCHIVE_NAME "ziti-prox-c-${PROJECT_VERSION}-${CPACK_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}.${archive_sfx}")

find_program(ZIP NAMES 7z)
if (ZIP)
    set(ZIP_OPTS a -tzip)
else()
    find_program(ZIP NAMES zip)
    if (ZIP)
        set(ZIP_OPTS "-jv")
    else()
        message("zip program not found")
    endif()
endif()

add_custom_target(ziti-prox-c-pack
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${ZITI_ARCHIVE_NAME}
        DEPENDS ziti-prox-c
        COMMAND ${ZIP} ${ZIP_OPTS} ${ZITI_ARCHIVE_NAME} $<TARGET_FILE:ziti-prox-c>
        )
