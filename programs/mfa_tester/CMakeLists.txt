add_executable(ziti_mfa ziti_mfa.cpp)
set_target_properties(ziti_mfa PROPERTIES
        CXX_STANDARD 20
)

target_link_libraries(ziti_mfa
        PUBLIC ziti
        PRIVATE CLI11::CLI11
)
