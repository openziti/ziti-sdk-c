project(sample-socket)

add_executable(ziti-ncat ziti-ncat.c)
target_link_libraries(ziti-ncat PUBLIC ziti)