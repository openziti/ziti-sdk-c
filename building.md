\page building Building the Project

The following steps should get your C SDK for Ziti building. C development is specific to your operating system and 
tool chain used. These steps should work properly for you but if your OS has variations you may need to adapt these steps accordingly.

[TOC]

\section Prerequisites

This repository expects the user to have at least a basic understanding of what a Ziti Network
is. To use this library it is also required to have a functioning Ziti Network availalbe to use.
To learn more about what Ziti is or how to learn how to setup a Ziti Network head over to [the official documentation
site](https://netfoundry.github.io/ziti-doc/ziti/overview.html).

\subsection prereqs Building Requirements

* [Cmake (3.12+)](https://cmake.org/install/)
* make sure cmake is on your path or replace the following `cmake` commands with the fully qualified path to the binary

\subsection initialization Project Initialization

The C SDK requires additional dependencies to be retreived. This is accomplished via the `git submodule` command. Fetch
the third party libs with git recursively. The following command can be used or if you use a GUI for git make sure you
initialize submodules:

```bash
$ git submodule update --init --recursive
```

\section building Building
\subsection linux_mac Linux/MacOS

Building the SDK on linux/mac can be accomplished with:

```bash
$ mkdir build
$ cd build
$ cmake .. && make
```

If you are cross compiling, you _must_ name the build directory as `build-$(uname -s)-$(uname -m)`

\subsection win Windows

The easiest method to build on windows is to open a "Developer Command Prompt for VS 2019" then locate the bat file at
the root of the project named `msvc-build.bat` and execute it. As always it's best to open the file to see the
individual steps performed will be before executing the bat file. The file outlines the steps needed to build the C SDK
on Windows. Effectively the script will:

* make a build folder
* make an x86 and an x64 folder
* run cmake (must be on your path) to generate the necessary files from source
* output a message like this showing you how to actually compile the project:

        cmake --build c:\git\github\ziti-sdk-c\build\x86 --config Debug
        cmake --build c:\git\github\ziti-sdk-c\build\x86 --config Release

        cmake --build c:\git\github\ziti-sdk-c\build\x64 --config Debug
        cmake --build c:\git\github\ziti-sdk-c\build\x64 --config Release
