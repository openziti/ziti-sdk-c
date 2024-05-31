macro(do_git out_var err_var)
    execute_process(
            COMMAND "git" ${ARGN}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE git_out
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_VARIABLE git_err
            ECHO_ERROR_VARIABLE
    )
    if (git_err)
        set(${err_var} ${git_err})
        unset(${out_var})
    else ()
        set(${out_var} "${git_out}")
        unset(${err_var})
    endif ()
endmacro(do_git)

function(get_version version_file version_var branch_var commit_var)
    do_git(GIT_INFO GIT_ERROR describe --always)
    if (GIT_ERROR)
        unset(GIT_INFO)
        message(NOTICE "getting version from ${version_file}")
        file(STRINGS ${version_file} ver_info)
        list(LENGTH ver_info ver_info_len)
        list(GET ver_info 0 GIT_INFO)
        list(GET ver_info 1 _branch)
        list(GET ver_info 2 _commit)
        set(${version_var} ${GIT_INFO} PARENT_SCOPE)
        set(${branch_var} ${_branch} PARENT_SCOPE)
        set(${commit_var} ${_commit} PARENT_SCOPE)
        return()
    endif ()

    do_git(_branch GIT_ERROR rev-parse --abbrev-ref HEAD)
    do_git(GIT_INFO GIT_ERROR describe --tags --long --first-parent HEAD)
    if (${GIT_INFO} MATCHES "^(.*)-([0-9]+)-([^-]*)") # <closest tag>-<distance>-<commit>
        set(_commit ${CMAKE_MATCH_3})
        if (${CMAKE_MATCH_2} EQUAL "0") #exact tag
            set(_ver ${CMAKE_MATCH_1})
        else ()
            string(JOIN "." _ver ${CMAKE_MATCH_1} ${CMAKE_MATCH_2})
        endif ()
    endif ()

    set(${version_var} ${_ver} PARENT_SCOPE)
    set(${branch_var} ${_branch} PARENT_SCOPE)
    set(${commit_var} ${_commit} PARENT_SCOPE)
endfunction()