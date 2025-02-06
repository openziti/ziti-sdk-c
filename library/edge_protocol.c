// Copyright (c) 2025. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "edge_protocol.h"
#include <protobuf-c/protobuf-c.h>
#include <ziti/enums.h>

const struct ziti_terminator_precedence_s PRECEDENCE = {
    .DEFAULT = ZITI__EDGE_CLIENT__PB__PRECEDENCE_VALUE__Default,
    .REQUIRED = ZITI__EDGE_CLIENT__PB__PRECEDENCE_VALUE__Required,
    .FAILED = ZITI__EDGE_CLIENT__PB__PRECEDENCE_VALUE__Failed,
};

const char* content_type_id(enum content_type ct) {
    const ProtobufCEnumValue *val = protobuf_c_enum_descriptor_get_value(
            &ziti__edge_client__pb__content_type__descriptor, ct);
    return val ? val->name : "<unexpected>";
}