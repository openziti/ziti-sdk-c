
function(get_version version_file version_var)
    execute_process(
            COMMAND git describe --tags HEAD
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_INFO
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_VARIABLE git_error
    )

    if (git_error)
        unset(GIT_INFO)
        message("getting version from ${version_file}")
        file(STRINGS ${version_file} ver_info)
        list(LENGTH ver_info ver_info_len)
        list(GET ver_info 0 GIT_INFO)
    endif ()

    if (${GIT_INFO} MATCHES "^v?([0-9]+\\.[0-9]+\\.[0-9]+)$")
        set(_ver ${CMAKE_MATCH_1})
    elseif (${GIT_INFO} MATCHES "^v?([0-9]+\\.[0-9]+\\.[0-9]+)-([0-9]+)-[^-]*")
        string(JOIN "." _ver ${CMAKE_MATCH_1} ${CMAKE_MATCH_2})
    endif ()

    set(${version_var} ${_ver} PARENT_SCOPE)
endfunction()