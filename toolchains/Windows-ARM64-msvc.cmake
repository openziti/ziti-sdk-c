# cross-compile for windows/arm64 on windows/x64 host with visual studio
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)
# setting CMAKE_GENERATOR_PLATFORM should be sufficient if you believe the doc, it results in build files
# that cause msbuild to that the ZERO_CHECK project doesn't contain the "Debug|x64" platform/config
# combination. running cmake with '-A ARCH64' avoids the msbuild failure.
set(CMAKE_GENERATOR_PLATFORM ARM64)
set(CMAKE_C_COMPILER cl.exe)