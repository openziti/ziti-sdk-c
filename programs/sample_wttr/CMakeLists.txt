
project(sample_wttr)

add_executable(sample_wttr sample_wttr.c ${ZITI_HEADER_FILES})
target_link_libraries(sample_wttr PUBLIC ziti)
