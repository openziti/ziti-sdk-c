# Building the Project

The following steps should get your C SDK for Ziti building. C development is specific to your operating system and 
tool chain used. These steps should work properly for you but if your OS has variations you may need to adapt these steps accordingly.

## Prerequisites

This repository expects the user to have at least a basic understanding of what a Ziti Network
is. To use this library it is also required to have a functioning Ziti Network available to use.
To learn more about what Ziti is or how to learn how to setup a Ziti Network head over to [the official documentation
site](https://openziti.io/).

## Building Requirements

* [cmake](https://cmake.org/install/)
* make sure cmake is on your path or replace the following `cmake` commands with the fully qualified path to the binary
* [vcpkg](https://github.com/microsoft/vcpkg) is now used for dependencies.

### Setting up vcpkg

To setup vcpkg you'll need to clone the actual vcpkg repository. The first step will have you set this environment variable.
It should be set to somewhere durable, such as wherever you check your projects into. The example commands below use $HOME/%USERPROFILE%
but you should probably change this to your liking.

Linux/MacOS:

* set/export an environment variable named `VCPKG_ROOT`. for example (use an appropriate location): `export VCPKG_ROOT=${HOME}/vcpkg`
* create the directory: `mkdir -p ${VCPKG_ROOT}`
* clone the vcpkg project: `git clone git@github.com:microsoft/vcpkg.git ${VCPKG_ROOT}`
* run the bootstrap-vcpkg for your platform: `${VCPKG_ROOT}/bootstrap-vcpkg.sh`

Windows: 
* set/export an environment variable named `VCPKG_ROOT`. for example (use an appropriate location): `SET VCPKG_ROOT=%USERPROFILE%\vcpkg`
* create the directory: `mkdir %VCPKG_ROOT%`
* clone the vcpkg project: `git clone git@github.com:microsoft/vcpkg.git %VCPKG_ROOT%`
* run the bootstrap-vcpkg for your platform: `%VCPKG_ROOT%/bootstrap-vcpkg.bat`

## Building

Make sure you have setup vcpkg (see above). Building the SDK is accomplished with the following commands from the 
checkout root. Replace the `--preset` value with the one that matches your needs or create your own preset. You
can run `cmake` from the checkout root with an `unknown` param passed to `--preset` to see the list of presets:
`cmake --preset unknown ${ZITI_SDK_C_ROOT}/.`

Build the SDK with:

```bash
mkdir build
cd build
cmake --preset ci-linux-x64 ..
cmake --build .
```

## Linting

Pull requests run a [codespell](https://github.com/codespell-project/codespell) check. The settings live in
`.codespellrc` at the checkout root, and both CI and local runs read that same file, so a run on your machine
matches the one in CI.

Install it once:

```bash
pip install codespell
```

Then check the tree from the checkout root:

```bash
codespell
```

If you have a configured build directory, the same check is wired up as a CMake target (developer mode only):

```bash
cmake --build build --target codespell
```

A clean tree exits 0. To let a flagged word through, add an `ignore-words-list` entry to `.codespellrc` rather than
to the workflow — codespell merges the two lists, so an entry in only one place is easy to lose track of.
