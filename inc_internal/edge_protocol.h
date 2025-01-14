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

    ContentTypeHelloType = 0,
    ContentTypePingType = 1,
    ContentTypeResultType = 2,
    ContentTypeLatencyType = 3,

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

    // TODO fix when available in protobuf definitions
    ContentTypeConnInspectRequest = 60798,
    ContentTypeConnInspectResponse = 60799,
    ContentTypeBindSuccess = 60800,

    ContentTypePostureResponse = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__PostureResponseType,
    ContentTypePostureResponseSuccess = ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__PostureResponseSuccessType,
};

enum header_id {
    ConnectionIdHeader = 0,
    ReplyForHeader = 1,
    ResultSuccessHeader = 2,
    HelloListenerHeader = 3,
    HelloVersionHeader = 4,

    // Headers in the range 128-255 inclusive will be reflected when creating replies
    ReflectedHeaderBitMask = 1 << 7,
    MaxReflectedHeader = (1 << 8) - 1,

    LatencyProbeTime = 128,
    UUIDHeader = 128,

    ConnIdHeader = 1000,
    SeqHeader = 1001,
    SessionTokenHeader = 1002,
    PublicKeyHeader = 1003,
    CostHeader = 1004,
    PrecedenceHeader = 1005,
    TerminatorIdentityHeader = 1006,
    TerminatorIdentitySecretHeader = 1007,
    CallerIdHeader = 1008,
    CryptoMethodHeader = 1009,
    FlagsHeader = 1010,
    AppDataHeader = 1011,
    RouterProvidedConnId = 1012,
    HealthStatusHeader = 1013,
    ErrorCodeHeader = 1014,
    TimestampHeader = 1015,
    TraceHopCountHeader = 1016,
    TraceHopTypeHeader = 1017,
    TraceHopIdHeader = 1018,
    TraceSourceRequestIdHeader = 1019,
    TraceError = 1020,
    ListenerId = 1021,
    ConnTypeHeader = 1022,
    SupportsInspectHeader = 1023,
    SupportsBindSuccessHeader = 1024,
    ConnectionMarkerHeader = 1025,
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
    EDGE_FIN = 1,
    // indicates that peer will send data messages with specially constructed UUID headers
    EDGE_TRACE_UUID = 1 << 1,
    // indicates that peer can accept multipart data messages
    EDGE_MULTIPART = 1 << 2,
    // indicates connection with stream semantics
    // this allows consolidation of payloads to lower overhead
    EDGE_STREAM = 1 << 3,
    // set on data message with multiple payloads
    EDGE_MULTIPART_MSG = 1 << 4,
};

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_EDGE_PROTOCOL_H
