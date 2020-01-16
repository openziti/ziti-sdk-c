project(sample-host)

add_executable(sample-host sample-host.c ${ZITI_HEADER_FILES})
target_link_libraries(sample-host PUBLIC ziti)