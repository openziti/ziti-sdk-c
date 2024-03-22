# if(NOT _VCPKG_FREEBSD_TOOLCHAIN)
#     set(_VCPKG_FREEBSD_TOOLCHAIN 1)
# endif()

# if(CMAKE_HOST_SYSTEM_NAME STREQUAL "FreeBSD")
#     set(CMAKE_CROSSCOMPILING OFF CACHE BOOL "")
# endif()

# set(CMAKE_SYSTEM_NAME FreeBSD CACHE STRING "")

# set(THREADS_PREFER_PTHREAD_FLAG ON)
# find_package(Threads REQUIRED)
# if(THREADS_HAVE_PTHREAD_ARG)
#     target_compile_options(PUBLIC ziti "-pthread")
# endif()
# if(CMAKE_THREAD_LIBS_INIT)
#     target_link_libraries(ziti "${CMAKE_THREAD_LIBS_INIT}")
# endif()
