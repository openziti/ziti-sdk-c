//
// Created by eugene on 3/5/19.
//

#ifndef ZT_SDK_MODEL_H
#define ZT_SDK_MODEL_H

/*
 * set of macros to help generate struct and function for our model;
 *
 * - DECLARE_MODEL(type, model_def) :
 *    `type` name of the struct,
 *    `model_def` - marco defining fields for the model
 *
 *    NOTE: matching MODEL_IMPL macro in model.c is used to generate function implementations
 *
 * Fields are defined with name, type, type modifier, and path (for JSON mapping)
 *
 * The following functions are generated:
 * - TYPE* parse_TYPE(json, len) -- parses json into an allocated struct
 *
 * - void free_TYPE(TYPE *obj)   -- frees struct
 *
 * - int dump_TYPE(TYPE *obj, int indent) -- prints the struct to `stdout`,
 *              `indent` is used for printing nested model objects
 */

#define FIELD_DECL(name, type, mod, path) mod(type) name;

/*
 * field type macros
 *
 * Nested model objects are supported as pointers and NULL-terminated arrays of pointers
 */
#define none(type) type
#define array(type) type**
#define ptr(type) type*

/*
 * Model declaration: struct type, and functions
 */
#define DECLARE_MODEL(type, model) \
typedef struct {\
model(FIELD_DECL) \
} type;\
type* parse_##type(const char* json, int json_len);\
type** parse_##type##_array(const char* json, int json_len);\
void free_##type(type* type);\
void free_##type##_array(type** arr); \
int dump_##type(type* type, int len);

typedef char* string;

#define ZITI_CTRL_VERSION(XX) \
XX(version, string, none, "$.version") \
XX(revision, string, none, "$.revision") \
XX(build_date, string, none, "$.buildDate")

#define ZITI_SERVICE_MODEL(XX) \
XX(id, string, none, "$.id") \
XX(name, string, none, "$.name") \
XX(dns_host, string, none, "$.dns.hostname") \
XX(dns_port, int, none, "$.dns.port") \
XX(hostable, bool, none, "$.hostable")

#define ZITI_CONFIG_MODEL(XX) \
XX(controller_url, string, none, "$.ztAPI") \
XX(cert, string, none, "$.id.cert") \
XX(key, string, none, "$.id.key") \
XX(ca, string, none, "$.id.ca")

#define ZITI_GATEWAY_MODEL(XX)\
XX(name, string, none, "$.name")\
XX(hostname, string, none, "$.hostname") \
XX(url_tls, string, none, "$.urls.tls")

#define ZITI_NET_SESSION_MODEL(XX) \
XX(token, string, none, "$.token")\
XX(id, string, none, "$.id") \
XX(hosting, bool, none, "$.hosting") \
XX(gateways, ziti_gateway, array, "$.gateways") \
XX(service_id, string, none, NULL)

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MODEL(ctrl_version, ZITI_CTRL_VERSION)

DECLARE_MODEL(nf_config, ZITI_CONFIG_MODEL)
DECLARE_MODEL(ziti_service, ZITI_SERVICE_MODEL)

DECLARE_MODEL(ziti_gateway, ZITI_GATEWAY_MODEL)
DECLARE_MODEL(ziti_net_session, ZITI_NET_SESSION_MODEL)

#ifdef __cplusplus
}
#endif

#endif //ZT_SDK_MODEL_H
