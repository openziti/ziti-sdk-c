project(zping)

add_executable(zping zping.c)
target_link_libraries(zping PUBLIC ziti)
