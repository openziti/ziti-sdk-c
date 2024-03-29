/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: edge_client.proto */

#ifndef PROTOBUF_C_edge_5fclient_2eproto__INCLUDED
#define PROTOBUF_C_edge_5fclient_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1005000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "google/protobuf/timestamp.pb-c.h"

typedef struct Ziti__EdgeClient__Pb__PostureResponses Ziti__EdgeClient__Pb__PostureResponses;
typedef struct Ziti__EdgeClient__Pb__PostureResponse Ziti__EdgeClient__Pb__PostureResponse;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__Macs Ziti__EdgeClient__Pb__PostureResponse__Macs;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__Domain Ziti__EdgeClient__Pb__PostureResponse__Domain;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__Process Ziti__EdgeClient__Pb__PostureResponse__Process;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__ProcessList Ziti__EdgeClient__Pb__PostureResponse__ProcessList;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__Woken Ziti__EdgeClient__Pb__PostureResponse__Woken;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__Unlocked Ziti__EdgeClient__Pb__PostureResponse__Unlocked;
typedef struct Ziti__EdgeClient__Pb__PostureResponse__SdkInfo Ziti__EdgeClient__Pb__PostureResponse__SdkInfo;


/* --- enums --- */

typedef enum _Ziti__EdgeClient__Pb__ContentType {
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__Zero = 0,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__ConnectType = 60783,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__StateConnectedType = 60784,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__StateClosedType = 60785,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DataType = 60786,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DialType = 60787,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DialSuccessType = 60788,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__DialFailedType = 60789,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__BindType = 60790,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UnbindType = 60791,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__StateSessionEndedType = 60792,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__ProbeType = 60793,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UpdateBindType = 60794,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__HealthEventType = 60795,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__TraceRouteType = 60796,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__TraceRouteResponseType = 60797,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UpdateTokenType = 60800,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UpdateTokenSuccessType = 60801,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__UpdateTokenFailureType = 60802,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__PostureResponseType = 10800,
  ZITI__EDGE_CLIENT__PB__CONTENT_TYPE__PostureResponseSuccessType = 10801
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(ZITI__EDGE_CLIENT__PB__CONTENT_TYPE)
} Ziti__EdgeClient__Pb__ContentType;

/* --- messages --- */

struct  Ziti__EdgeClient__Pb__PostureResponses
{
  ProtobufCMessage base;
  size_t n_responses;
  Ziti__EdgeClient__Pb__PostureResponse **responses;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSES__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_responses__descriptor) \
, 0,NULL }


struct  Ziti__EdgeClient__Pb__PostureResponse__Macs
{
  ProtobufCMessage base;
  size_t n_addresses;
  char **addresses;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__MACS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__macs__descriptor) \
, 0,NULL }


struct  Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem
{
  ProtobufCMessage base;
  char *type;
  char *version;
  char *build;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__OPERATING_SYSTEM__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__operating_system__descriptor) \
, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string }


struct  Ziti__EdgeClient__Pb__PostureResponse__Domain
{
  ProtobufCMessage base;
  char *name;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__DOMAIN__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__domain__descriptor) \
, (char *)protobuf_c_empty_string }


struct  Ziti__EdgeClient__Pb__PostureResponse__Process
{
  ProtobufCMessage base;
  char *path;
  protobuf_c_boolean isrunning;
  char *hash;
  size_t n_signerfingerprints;
  char **signerfingerprints;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__PROCESS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__process__descriptor) \
, (char *)protobuf_c_empty_string, 0, (char *)protobuf_c_empty_string, 0,NULL }


struct  Ziti__EdgeClient__Pb__PostureResponse__ProcessList
{
  ProtobufCMessage base;
  size_t n_processes;
  Ziti__EdgeClient__Pb__PostureResponse__Process **processes;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__PROCESS_LIST__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__process_list__descriptor) \
, 0,NULL }


struct  Ziti__EdgeClient__Pb__PostureResponse__Woken
{
  ProtobufCMessage base;
  Google__Protobuf__Timestamp *time;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__WOKEN__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__woken__descriptor) \
, NULL }


struct  Ziti__EdgeClient__Pb__PostureResponse__Unlocked
{
  ProtobufCMessage base;
  Google__Protobuf__Timestamp *time;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__UNLOCKED__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__unlocked__descriptor) \
, NULL }


struct  Ziti__EdgeClient__Pb__PostureResponse__SdkInfo
{
  ProtobufCMessage base;
  char *appid;
  char *appversion;
  char *branch;
  char *revision;
  char *type;
  char *version;
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__SDK_INFO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__sdk_info__descriptor) \
, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string }


typedef enum {
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE__NOT_SET = 0,
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_MACS = 1,
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_OS = 2,
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_PROCESS_LIST = 3,
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_DOMAIN = 4,
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_WOKEN = 5,
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_UNLOCKED = 6,
  ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_SDK_INFO = 7
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE__CASE)
} Ziti__EdgeClient__Pb__PostureResponse__TypeCase;

struct  Ziti__EdgeClient__Pb__PostureResponse
{
  ProtobufCMessage base;
  Ziti__EdgeClient__Pb__PostureResponse__TypeCase type_case;
  union {
    Ziti__EdgeClient__Pb__PostureResponse__Macs *macs;
    Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem *os;
    Ziti__EdgeClient__Pb__PostureResponse__ProcessList *processlist;
    Ziti__EdgeClient__Pb__PostureResponse__Domain *domain;
    Ziti__EdgeClient__Pb__PostureResponse__Woken *woken;
    Ziti__EdgeClient__Pb__PostureResponse__Unlocked *unlocked;
    Ziti__EdgeClient__Pb__PostureResponse__SdkInfo *sdkinfo;
  };
};
#define ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ziti__edge_client__pb__posture_response__descriptor) \
, ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE__NOT_SET, {0} }


/* Ziti__EdgeClient__Pb__PostureResponses methods */
void   ziti__edge_client__pb__posture_responses__init
                     (Ziti__EdgeClient__Pb__PostureResponses         *message);
size_t ziti__edge_client__pb__posture_responses__get_packed_size
                     (const Ziti__EdgeClient__Pb__PostureResponses   *message);
size_t ziti__edge_client__pb__posture_responses__pack
                     (const Ziti__EdgeClient__Pb__PostureResponses   *message,
                      uint8_t             *out);
size_t ziti__edge_client__pb__posture_responses__pack_to_buffer
                     (const Ziti__EdgeClient__Pb__PostureResponses   *message,
                      ProtobufCBuffer     *buffer);
Ziti__EdgeClient__Pb__PostureResponses *
       ziti__edge_client__pb__posture_responses__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ziti__edge_client__pb__posture_responses__free_unpacked
                     (Ziti__EdgeClient__Pb__PostureResponses *message,
                      ProtobufCAllocator *allocator);
/* Ziti__EdgeClient__Pb__PostureResponse__Macs methods */
void   ziti__edge_client__pb__posture_response__macs__init
                     (Ziti__EdgeClient__Pb__PostureResponse__Macs         *message);
/* Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem methods */
void   ziti__edge_client__pb__posture_response__operating_system__init
                     (Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem         *message);
/* Ziti__EdgeClient__Pb__PostureResponse__Domain methods */
void   ziti__edge_client__pb__posture_response__domain__init
                     (Ziti__EdgeClient__Pb__PostureResponse__Domain         *message);
/* Ziti__EdgeClient__Pb__PostureResponse__Process methods */
void   ziti__edge_client__pb__posture_response__process__init
                     (Ziti__EdgeClient__Pb__PostureResponse__Process         *message);
/* Ziti__EdgeClient__Pb__PostureResponse__ProcessList methods */
void   ziti__edge_client__pb__posture_response__process_list__init
                     (Ziti__EdgeClient__Pb__PostureResponse__ProcessList         *message);
/* Ziti__EdgeClient__Pb__PostureResponse__Woken methods */
void   ziti__edge_client__pb__posture_response__woken__init
                     (Ziti__EdgeClient__Pb__PostureResponse__Woken         *message);
/* Ziti__EdgeClient__Pb__PostureResponse__Unlocked methods */
void   ziti__edge_client__pb__posture_response__unlocked__init
                     (Ziti__EdgeClient__Pb__PostureResponse__Unlocked         *message);
/* Ziti__EdgeClient__Pb__PostureResponse__SdkInfo methods */
void   ziti__edge_client__pb__posture_response__sdk_info__init
                     (Ziti__EdgeClient__Pb__PostureResponse__SdkInfo         *message);
/* Ziti__EdgeClient__Pb__PostureResponse methods */
void   ziti__edge_client__pb__posture_response__init
                     (Ziti__EdgeClient__Pb__PostureResponse         *message);
size_t ziti__edge_client__pb__posture_response__get_packed_size
                     (const Ziti__EdgeClient__Pb__PostureResponse   *message);
size_t ziti__edge_client__pb__posture_response__pack
                     (const Ziti__EdgeClient__Pb__PostureResponse   *message,
                      uint8_t             *out);
size_t ziti__edge_client__pb__posture_response__pack_to_buffer
                     (const Ziti__EdgeClient__Pb__PostureResponse   *message,
                      ProtobufCBuffer     *buffer);
Ziti__EdgeClient__Pb__PostureResponse *
       ziti__edge_client__pb__posture_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ziti__edge_client__pb__posture_response__free_unpacked
                     (Ziti__EdgeClient__Pb__PostureResponse *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Ziti__EdgeClient__Pb__PostureResponses_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponses *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__Macs_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__Macs *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__OperatingSystem *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__Domain_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__Domain *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__Process_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__Process *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__ProcessList_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__ProcessList *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__Woken_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__Woken *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__Unlocked_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__Unlocked *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse__SdkInfo_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse__SdkInfo *message,
                  void *closure_data);
typedef void (*Ziti__EdgeClient__Pb__PostureResponse_Closure)
                 (const Ziti__EdgeClient__Pb__PostureResponse *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    ziti__edge_client__pb__content_type__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_responses__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__macs__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__operating_system__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__domain__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__process__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__process_list__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__woken__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__unlocked__descriptor;
extern const ProtobufCMessageDescriptor ziti__edge_client__pb__posture_response__sdk_info__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_edge_5fclient_2eproto__INCLUDED */
