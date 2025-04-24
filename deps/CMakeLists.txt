
include(FetchContent)

# allow downstream projects to pull tlsuv on their own
if (NOT TARGET tlsuv)
    if (tlsuv_DIR)
        add_subdirectory(${tlsuv_DIR}
                ${CMAKE_CURRENT_BINARY_DIR}/tlsuv)
    else ()
        FetchContent_Declare(tlsuv
                GIT_REPOSITORY https://github.com/openziti/tlsuv.git
                GIT_TAG v0.34.1
        )
        FetchContent_MakeAvailable(tlsuv)
    endif (tlsuv_DIR)
endif () # tlsuv TARGET
