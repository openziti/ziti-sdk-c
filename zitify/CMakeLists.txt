
if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

    add_library(zitify SHARED
            zitify.cpp)

    target_link_libraries(zitify PRIVATE ziti)

    set(zitify_archive zitify-${PROJECT_VERSION}-${CPACK_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}.zip)

    add_custom_target(zitify-pack
            BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${zitify_archive}
            ALL
            DEPENDS zitify
            COMMAND ${ZIP} ${ZIP_OPTS} ${zitify_archive} $<TARGET_FILE:zitify> ${CMAKE_CURRENT_SOURCE_DIR}/zitify
            )
else()
    add_custom_target(zitify-pack
            COMMAND echo "zitify not yet implemented on ${CMAKE_SYSTEM_NAME} platform"
            )

endif ()