project(sample_http_link)

add_executable(sample_http_link sample_http_link.c)
target_link_libraries(sample_http_link PUBLIC ziti)
