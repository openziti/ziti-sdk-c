// Copyright (c) 2020-2024. NetFoundry Inc.
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


#ifndef ZITI_SDK_EDGE_PROTOCOL_H
#define ZITI_SDK_EDGE_PROTOCOL_H

#include <stdint.h>
#include "../library/proto/edge_client.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

enum content_type {

    ContentTypeHelloType = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__Hello,
    ContentTypePingType = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__Ping,
    ContentTypeResultType = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__Result,
    ContentTypeLatencyType = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__Latency,

    ContentTypeConnect = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__ConnectType,
    ContentTypeStateConnected = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__StateConnectedType,
    ContentTypeStateClosed = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__StateClosedType,
    ContentTypeData = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DataType,
    ContentTypeDial = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DialType,
    ContentTypeDialSuccess = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DialSuccessType,
    ContentTypeDialFailed = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DialFailedType,
    ContentTypeBind = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__BindType,
    ContentTypeUnbind = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UnbindType,

    ContentTypeUpdateToken = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UpdateTokenType,
    ContentTypeUpdateTokenSuccess = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UpdateTokenSuccessType,
    ContentTypeUpdateTokenFailure = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UpdateTokenFailureType,

    ContentTypeConnInspectRequest = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__ConnInspectRequest,
    ContentTypeConnInspectResponse = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__ConnInspectResponse,
    ContentTypeBindSuccess = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__BindSuccess,

    ContentTypePostureResponse = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__PostureResponseType,
    ContentTypePostureResponseSuccess = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__PostureResponseSuccessType,
};

enum header_id {
    ReplyForHeader = 1,
    ResultSuccessHeader = 2,
    HelloVersionHeader = 4,

    LatencyProbeTime = 128,
    UUIDHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__UUID,

    ConnIdHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__ConnId,
    SeqHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__Seq,
    SessionTokenHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__SessionToken,
    PublicKeyHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__PublicKey,
    CostHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__Cost,
    PrecedenceHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__Precedence,
    TerminatorIdentityHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__TerminatorIdentity,
    TerminatorIdentitySecretHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__TerminatorIdentitySecret,
    CallerIdHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__CallerId,
    CryptoMethodHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__CryptoMethod,
    FlagsHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__Flags,
    AppDataHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__AppData,
    RouterProvidedConnId = ZITI__EDGE_CLIENT__PB__HEADER_ID__RouterProvidedConnId,
    ErrorCodeHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__ErrorCode,
    ListenerId = ZITI__EDGE_CLIENT__PB__HEADER_ID__ListenerId,
    ConnTypeHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__ConnType,
    SupportsInspectHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__SupportsInspect,
    SupportsBindSuccessHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__SupportsBindSuccess,
    ConnectionMarkerHeader = ZITI__EDGE_CLIENT__PB__HEADER_ID__ConnectionMarker,
};

typedef uint8_t connection_type_t;
enum connection_type {
    ConnTypeInvalid,
    ConnTypeDial = 1,
    ConnTypeBind = 2,
    ConnTypeUnknown = 3,
};

enum crypto_method {
    CryptoMethodLibsodium = 0,
    CryptoMethodAES256GCM = 1,
};

enum edge_flag {
    // half close connection no more data messages are expected
    // after receipt of message with this flag
    EDGE_FIN = ZITI__EDGE_CLIENT__PB__FLAG__FIN,
    // indicates that peer will send data messages with specially constructed UUID headers
    EDGE_TRACE_UUID = ZITI__EDGE_CLIENT__PB__FLAG__TRACE_UUID,
    // indicates that peer can accept multipart data messages
    EDGE_MULTIPART = ZITI__EDGE_CLIENT__PB__FLAG__MULTIPART,
    // indicates connection with stream semantics
    // this allows consolidation of payloads to lower overhead
    EDGE_STREAM = ZITI__EDGE_CLIENT__PB__FLAG__STREAM,
    // set on data message with multiple payloads
    EDGE_MULTIPART_MSG = ZITI__EDGE_CLIENT__PB__FLAG__MULTIPART_MSG,
};

typedef enum ziti_terminator_precedence_e {
    PRECEDENCE_DEFAULT = ZITI__EDGE_CLIENT__PB__PRECEDENCE_VALUE__Default,
    PRECEDENCE_REQUIRED = ZITI__EDGE_CLIENT__PB__PRECEDENCE_VALUE__Required,
    PRECEDENCE_FAILED = ZITI__EDGE_CLIENT__PB__PRECEDENCE_VALUE__Failed,
} ziti_terminator_precedence;

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_EDGE_PROTOCOL_H
