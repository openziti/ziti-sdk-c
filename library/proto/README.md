Ziti Protobuf
------

This folder contains protobuf support files.

This guide is only targeted for OpenZiti developers making changes to the library. 
A consuming application just needs to add `protobuf-c` dependency

The source of protobuf definitions comes from https://github.com/openziti/sdk-golang/blob/main/pb/edge_client_pb/edge_client.proto
Any time definitions are modified, this project has to be updated.

# Prerequisites 
- Protobuf compilers: `protoc`, `protoc-gen-c`. Install them according to your development environment

# Steps
- copy `edge_client.proto` from the link above
- generate protobuf implementation files:
     in your build directory: `$ cmake --build . --target generate-protobuf`.
- make necessary changes in the code that uses protobuf objects/functions
- commit the content of this directory, create PR, etc