project(nwp)

add_executable(nwp nwp.c)
target_link_libraries(nwp PUBLIC ziti)