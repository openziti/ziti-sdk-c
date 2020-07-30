project(wzcat)

add_executable(wzcat ziti_ws.c)
target_link_libraries(wzcat PUBLIC ziti)
