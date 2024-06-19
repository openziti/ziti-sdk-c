add_executable(ziti_mfa ziti_mfa.cpp)
target_link_libraries(ziti_mfa
        PUBLIC ziti
        PRIVATE CLI11::CLI11
)
