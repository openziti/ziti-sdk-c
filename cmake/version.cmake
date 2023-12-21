
function(get_version version_file version_var branch_var commit_var)
    execute_process(
            COMMAND git describe --tags --match=[0-9]* HEAD
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_INFO
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_VARIABLE git_error
    )

    if (NOT git_error)
        execute_process(
                COMMAND git rev-parse --abbrev-ref HEAD
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE branch
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        # Get the latest abbreviated commit hash of the working branch
        execute_process(
                COMMAND git log -1 --format=%h
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE commit
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    endif ()

    if (git_error)
        unset(GIT_INFO)
        message("getting version from ${version_file}")
        file(STRINGS ${version_file} ver_info)
        list(LENGTH ver_info ver_info_len)
        list(GET ver_info 0 GIT_INFO)
        list(GET ver_info 1 branch)
        list(GET ver_info 2 commit)
    endif ()

    if (${GIT_INFO} MATCHES "^v?([0-9]+\\.[0-9]+\\.[0-9]+)$")
        set(_ver ${CMAKE_MATCH_1})
    elseif (${GIT_INFO} MATCHES "^v?([0-9]+\\.[0-9]+\\.[0-9]+)-([0-9]+)-[^-]*")
        string(JOIN "." _ver ${CMAKE_MATCH_1} ${CMAKE_MATCH_2})
    endif ()

    set(${version_var} ${_ver} PARENT_SCOPE)
    set(${branch_var} ${branch} PARENT_SCOPE)
    set(${commit_var} ${commit} PARENT_SCOPE)
endfunction()