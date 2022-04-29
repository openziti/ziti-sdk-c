project(sample-socket)

add_executable(ziti-ncat ziti-ncat.c)
target_link_libraries(ziti-ncat PUBLIC ziti)

add_executable(ziti-socket-sample ziti-fd-client.c)
target_link_libraries(ziti-socket-sample PUBLIC ziti)

add_executable(ziti-http-get ziti-http-get.c)
target_link_libraries(ziti-http-get PUBLIC ziti http-parser)