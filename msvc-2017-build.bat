@echo off & setlocal
pushd .
set CSDK_HOME=%~dp0
cd /d %CSDK_HOME%

set BUILDFOLDER=%CSDK_HOME%build2017

mkdir %BUILDFOLDER%
pushd %BUILDFOLDER%

cmake .. -G "Visual Studio 15 2017" -A x64 -DCMAKE_INSTALL_INCLUDEDIR=include -DCMAKE_INSTALL_LIBDIR=lib
ECHO Build from cmake using: 
ECHO     cmake --build %BUILDFOLDER% --config Debug
ECHO     cmake --build %BUILDFOLDER% --config Release
ECHO 
ECHO Or open %BUILDFOLDER%\ziti-sdk.sln

goto end

REM this is holdover from before protobuf files were checked in.
REM leaving this behind for history if ever needed


@echo off & setlocal
set CSDK_HOME=%~dp0
pushd %CSDK_HOME%

set BUILDFOLDER=build
mkdir %CSDK_HOME%\%BUILDFOLDER%\protobuf_working_folder
pushd %CSDK_HOME%\%BUILDFOLDER%\protobuf_working_folder

git clone https://github.com/protocolbuffers/protobuf

cd %CSDK_HOME%\%BUILDFOLDER%\protobuf_working_folder\protobuf
set PROTOBUF_HOME=%CD%
cd cmake
mkdir %BUILDFOLDER%
cd %BUILDFOLDER%
set PROTO_C_PATH=%PROTOBUF_HOME%\cmake\%BUILDFOLDER%\Release
cmake -G "Visual Studio 15 2017" -A x64 .. -Dprotobuf_BUILD_TESTS=OFF
cmake --build . --config Release
popd

pushd %CSDK_HOME%\deps\protobuf-c\build-cmake
mkdir %BUILDFOLDER%
cd %BUILDFOLDER%
set CMAKE_INCLUDE_PATH=%PROTOBUF_HOME%\src
set CMAKE_LIBRARY_PATH=%PROTOBUF_HOME%\cmake\%BUILDFOLDER%\Release
set PROTO_C_GEN_C=%cd%\Release
cmake -G "Visual Studio 15 2017" -A x64 .. -DCMAKE_CXX_FLAGS_RELEASE=/MT
cmake --build . --config Release
popd

mkdir %BUILDFOLDER%\cmake
cd %BUILDFOLDER%\cmake
mkdir lib
copy %PROTO_C_PATH%\* lib
copy %PROTO_C_GEN_C%\* lib

echo USING proto_c     : %cd%\lib
echo USING protoc_gen_c: %cd%\lib

cmake -G "Visual Studio 15 2017" -A x64 ..\.. -DCMAKE_INSTALL_INCLUDEDIR=include -Dproto_c=%cd%\lib -Dprotoc_gen_c=%cd%\lib
cmake --build . --config Debug
REM cmake --build . --config Release
goto end

:abnormalend
echo TERMINATED UNEXPECTEDLY

:end
popd
