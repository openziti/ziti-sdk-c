project(sample-socket)

add_executable(ziti-ncat ziti-ncat.c)
target_link_libraries(ziti-ncat PUBLIC ziti)

add_executable(ziti-socat ziti-fd-client.c)
target_link_libraries(ziti-socat PUBLIC ziti)