message("CMAKE_SYSTEM_NAME=${CMAKE_HOST_SYSTEM_NAME}")
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_GENERATOR_PLATFORM ARM64)
# from VS command prompt, run `vsdevcmd -arch=arm64 -host_arch=amd64 -winsdk=10.0.19041.0`
# C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.29.30133\bin\HostX64\ARM64
#set(VCINSTALLDIR "C:/Program Files/Microsoft Visual Studio/2022/Community/VC")
set(CMAKE_C_COMPILER cl.exe)
