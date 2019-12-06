Ziti C SDK - Setup for Development
==================================

The following steps should get your C SDK for Ziti building. C development is specific to your operating system and tool chain used. 
These steps should work properly for you but if your OS has variations you may need to adapt these steps accordingly.

Status
------

.. image:: https://travis-ci.org/netfoundry/ziti-sdk-c.svg?branch=master
    :target: https://travis-ci.org/netfoundry/ziti-sdk-c

Prerequisites
-------------

Build
_____

* Cmake_ (3.12+)


Init
----

The C SDK requires additional dependencies to be retreived. This is accomplished via the :code:`git submodule` command. Fetch third party libs using:

.. code-block:: bash

    $ git submodule update --init --recursive

Build
-------

Linux/MacOS
___________

Building the SDK on linux/mac can be accomplished with:

.. code-block:: bash

    $ mkdir build
    $ cd build
    $ cmake .. && make

If you are cross compiling, you _must_ name the build directory as :code:`build-$(uname -s)-$(uname -m)`

Windows
_______

The easiest method to build on windows is to open a "Developer Command Prompt for VS 2019" and execute :code:`msvc-build.bat`.
Open that file to see the individual steps needed to build the C SDK on Windows. The steps the script will do are:

.. code-block:: bash

    mkdir build
    cd build
    cmake .. -DCMAKE_INSTALL_INCLUDEDIR=include -DCMAKE_INSTALL_LIBDIR=lib
    cmake --build . --config Debug [Release]


Getting Help
------------
Please use these community resources for getting help. We use GitHub issues_ for tracking bugs and feature requests and have limited bandwidth
to address them.

- Read the docs_
- Join our `Developer Community`_
- Participate in discussion on Discourse_


.. _Developer Community: https://developer.netfoundry.io
.. _docs: https://netfoundry.github.io/ziti-doc/ziti/overview.html
.. _Discourse: https://netfoundry.discourse.group/
.. _issues: https://github.com/NetFoundry/ziti-sdk-c/issues
.. _cmake: https://cmake.org/install/

.. |copy|   unicode:: U+000A9 .. COPYRIGHT SIGN

Copyright |copy| 2018-2019. NetFoundry, Inc.
