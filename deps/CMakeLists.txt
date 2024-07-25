
include(FetchContent)

if (tlsuv_DIR)
    add_subdirectory(${tlsuv_DIR}
            ${CMAKE_CURRENT_BINARY_DIR}/tlsuv)
else ()

    FetchContent_Declare(tlsuv
            GIT_REPOSITORY https://github.com/openziti/tlsuv.git
            GIT_TAG v0.30.1
            )
    FetchContent_MakeAvailable(tlsuv)

endif (tlsuv_DIR)




