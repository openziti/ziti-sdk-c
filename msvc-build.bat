@echo off & setlocal
pushd .
set CSDK_HOME=%~dp0
cd /d %CSDK_HOME%

set BUILDFOLDER=%CSDK_HOME%build

mkdir %BUILDFOLDER%
mkdir %BUILDFOLDER%\x86
mkdir %BUILDFOLDER%\x64
pushd %BUILDFOLDER%

pushd %BUILDFOLDER%\x86
cmake ..\.. -G "Visual Studio 16 2019" -A Win32 -DCMAKE_INSTALL_INCLUDEDIR=include -DCMAKE_INSTALL_LIBDIR=lib
popd

pushd %BUILDFOLDER%\x64
cmake ..\.. -G "Visual Studio 16 2019" -A x64 -DCMAKE_INSTALL_INCLUDEDIR=include -DCMAKE_INSTALL_LIBDIR=lib
popd

ECHO Build from cmake using: 
ECHO     cmake --build %BUILDFOLDER%\x86 --config Debug
ECHO     cmake --build %BUILDFOLDER%\x86 --config Release
ECHO. 
ECHO     cmake --build %BUILDFOLDER%\x64 --config Debug
ECHO     cmake --build %BUILDFOLDER%\x64 --config Release
ECHO. 
ECHO Or open %BUILDFOLDER%\ziti-sdk.sln

goto end

:blank
set BUILDFOLDER=%CSDK_HOME%\build
GOTO params_set


REM this is holdover from before protobuf files were checked in.
REM leaving this behind for history if ever needed

cd /D "%~dp0"
set CSDK_HOME=%CD%
pushd .
set BUILDFOLDER=build
mkdir %CSDK_HOME%\%BUILDFOLDER%\protobuf_working_folder
pushd %CSDK_HOME%\%BUILDFOLDER%\protobuf_working_folder

git clone https://github.com/protocolbuffers/protobuf
git clone https://github.com/protobuf-c/protobuf-c.git

pushd %CSDK_HOME%\%BUILDFOLDER%\protobuf_working_folder\protobuf
REM git checkout 3.7.x
set PROTOBUF_HOME=%CD%
cd cmake
mkdir %BUILDFOLDER%
cd %BUILDFOLDER%
set PROTO_C_PATH=%PROTOBUF_HOME%\cmake\%BUILDFOLDER%\Release
cmake .. -Dprotobuf_BUILD_TESTS=OFF
cmake --build . --config Release
popd

cd protobuf-c\build-cmake
mkdir %BUILDFOLDER%
cd %BUILDFOLDER%
set CMAKE_INCLUDE_PATH=%PROTOBUF_HOME%\src
set CMAKE_LIBRARY_PATH=%PROTOBUF_HOME%\cmake\%BUILDFOLDER%\Release
set PROTO_C_GEN_C=%cd%\Release
cmake .. -DCMAKE_CXX_FLAGS_RELEASE=/MT
cmake --build . --config Release
popd

mkdir %BUILDFOLDER%\cmake
cd %BUILDFOLDER%\cmake
mkdir lib
copy %PROTO_C_PATH%\* lib
copy %PROTO_C_GEN_C%\* lib

cmake ..\.. -DCMAKE_INSTALL_INCLUDEDIR=include -Dproto_c=%cd%\lib -Dprotoc_gen_c=%cd%\lib
cmake --build . --config Debug
REM cmake --build . --config Release


goto end

:abnormalend
echo TERMINATED UNEXPECTEDLY

:end
popd

