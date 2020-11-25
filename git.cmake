# Get the current working branch
execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash of the working branch
execute_process(
        COMMAND git log -1 --format=%h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# capture build date
if (WIN32)
execute_process(
        COMMAND	powershell get-date -uf '+%a-%m/%d/%Y-%H:%M:%S-%Z'
		OUTPUT_VARIABLE	BUILD_DATE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
else()
execute_process(
        COMMAND	date +%a-%m/%d/%Y-%H:%M:%S-%Z
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE BUILD_DATE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
endif()

# lookup most recent tag to derive version
execute_process(
        COMMAND git describe --tags HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_INFO
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(${GIT_INFO} MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+)$")
    set(ver ${GIT_INFO})
elseif(${GIT_INFO} MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+)-([0-9]+)-[^-]*")
    string(JOIN "." ver ${CMAKE_MATCH_1} ${CMAKE_MATCH_2})
endif()
message("project version: ${ver} (derived from git)")



