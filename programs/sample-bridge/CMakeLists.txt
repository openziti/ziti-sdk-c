project(sample-socket)

add_executable(ziti-ncat ziti-ncat.c)
target_link_libraries(ziti-ncat PUBLIC ziti)

add_executable(ziti-socket-sample ziti-fd-client.c)
target_link_libraries(ziti-socket-sample PUBLIC ziti)