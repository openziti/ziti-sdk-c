
include(${ziti-deps_BINARY_DIR}/Catch2/${CMAKE_INSTALL_LIBDIR}/cmake/Catch2/Catch.cmake)
include(${ziti-deps_BINARY_DIR}/Catch2/${CMAKE_INSTALL_LIBDIR}/cmake/Catch2/ParseAndAddCatchTests.cmake)

add_executable(all_tests
        all_tests.cpp
        test_model.cpp)
set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)

target_include_directories(all_tests PRIVATE ${ziti-deps_BINARY_DIR}/Catch2/include)
target_link_libraries(all_tests
        PRIVATE ziti)

include(CTest)
ParseAndAddCatchTests(all_tests)

