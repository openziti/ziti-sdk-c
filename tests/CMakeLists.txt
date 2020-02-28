
add_executable(all_tests
        all_tests.cpp
        test_model.cpp ctrl_tests.cpp)
set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)

target_include_directories(all_tests
        PRIVATE ${CMAKE_SOURCE_DIR}/inc_internal)

target_link_libraries(all_tests
        PRIVATE ziti)

include(CTest)
add_test(quick_tests all_tests "exclude:[integ]")

