/*
Copyright (c) 2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


#ifndef ZITI_SDK_EDGE_PROTOCOL_H
#define ZITI_SDK_EDGE_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

enum content_type {

    ContentTypeHelloType = 0,
    ContentTypePingType = 1,
    ContentTypeResultType = 2,
    ContentTypeLatencyType = 3,

    ContentTypeEdge = 0xED6E,
    ContentTypeConnect = 60783,
    ContentTypeStateConnected = 60784,
    ContentTypeStateClosed = 60785,
    ContentTypeData = 60786,
    ContentTypeDial = 60787,
    ContentTypeDialSuccess = 60788,
    ContentTypeDialFailed = 60789,
    ContentTypeBind = 60790,
    ContentTypeUnbind = 60791,
    ContentTypeStateSessionEnded = 60792,
	ContentTypeProbe             = 60793,
	ContentTypeUpdateBind        = 60794,
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
};

enum crypto_method {
    CryptoMethodLibsodium = 0,
    CryptoMethodAES256GCM = 1,
};

enum edge_flag {
    EDGE_FIN = 1,
};

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_EDGE_PROTOCOL_H
