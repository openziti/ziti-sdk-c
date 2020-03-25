project(sample_enroll)

add_executable(sample_enroll sample_enroll.c)
target_link_libraries(sample_enroll PUBLIC ziti)
