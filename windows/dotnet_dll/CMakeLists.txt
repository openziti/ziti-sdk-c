cmake_minimum_required(VERSION 3.10)


# use prefix length to trim path for logging, see inc_internal/utils.h __FILENAME__
string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

link_directories("${protobuf_link_directory}") #note link_directories needs to come BEFORE add_executable

set(SOURCE_FILES
	zitidll.cpp 
	csharp_utils.c
)
add_library(ziti_dll SHARED ${SOURCE_FILES} ${HEADER_FILES})


target_include_directories(ziti_dll
	PRIVATE
	"${CMAKE_CURRENT_SOURCE_DIR}/includes"
	"${CMAKE_SOURCE_DIR}/deps/uv-mbed/include"
	"${CMAKE_SOURCE_DIR}/deps/uv-mbed/libuv/include"
	"${CMAKE_SOURCE_DIR}/deps/uv-mbed/mbedtls/include"
	"${CMAKE_SOURCE_DIR}/deps/uv-mbed/win32/include"
	"${CMAKE_SOURCE_DIR}/deps/subcommand"


	"${CMAKE_SOURCE_DIR}/includes"
	"${CMAKE_SOURCE_DIR}/library"
	"${CMAKE_SOURCE_DIR}/inc_internal"
	)

target_link_libraries(ziti_dll mbedtls uv_a ziti)
