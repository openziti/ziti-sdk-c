/*
Copyright 2019 Netfoundry, Inc.

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

#include "mbed_p11.h"
#include "p11_errors.h"

#if _WIN32
#define strncasecmp _strnicmp
#else
#include <dlfcn.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <utils.h>
#include <nf/errors.h>


static int p11_getopt(const char *q, const char *opt, char *out, size_t maxout);

static int mp11_init(mp11_context *p11, const char *lib, const char *slot, const char *pin);

static int mp11_get_key(mbedtls_pk_context *key, mp11_context *ctx, const char *id, const char *label);

static mp11_context CTX;

int mp11_load_key(mbedtls_pk_context *key, const char *path, const char *opts) {
    PREPF(mbed, fmt_mbederr);


    char pin[32];
    p11_getopt(opts, "pin", pin, sizeof(pin));
    char slot[32];
    p11_getopt(opts, "slot", slot, sizeof(slot));

    if (CTX.lib == NULL) {
        TRY(mbed, mp11_init(&CTX, path, slot, pin));
    }

    char id[32];
    p11_getopt(opts, "id", id, sizeof(id));
    char label[128];
    p11_getopt(opts, "label", label, sizeof(label));

    TRY(mbed, mp11_get_key(key, &CTX, id, label));
    CATCH(mbed) {
        return ERR(mbed);
    }
    return ZITI_OK;
}

static int mp11_get_key(mbedtls_pk_context *key, mp11_context *ctx, const char *idstr, const char *label) {
    PREPCF(p11, non_zero, p11_strerror);

    NEWP(p11_key, mp11_key_ctx);

    CK_ULONG cls = CKO_PRIVATE_KEY;
    char id[32];
    CK_ULONG idlen;


    CK_ULONG qcount = 1;
    CK_ATTRIBUTE query[3] = {
            {CKA_CLASS, &cls, sizeof(cls)}
    };

    if (idstr != NULL && strcmp(idstr, "") != 0) {
        idlen = (strlen(idstr) + 1) / 2;
        for (int idx = 0; idx < idlen; idx++) {
            sscanf(idstr + 2 * idx, "%2hhx", &id[idx]);
        }
        // parse id
        query[qcount].type = CKA_ID;
        query[qcount].pValue = id;
        query[qcount].ulValueLen = idlen;

        qcount++;
    }

    if (label != NULL && strcmp(label, "") != 0) {
        query[qcount].type = CKA_LABEL;
        query[qcount].pValue = label;
        query[qcount].ulValueLen = strlen(label);

        qcount++;
    }

    if (qcount < 2) {
        ZITI_LOG(ERROR, "no id/label specified for key");
        TRY(p11, CKR_KEY_NEEDED);
    }

    CK_ULONG objc;
    TRY(p11, ctx->funcs->C_FindObjectsInit(ctx->session, query, qcount));
    TRY(p11, ctx->funcs->C_FindObjects(ctx->session, &p11_key->priv_handle, 1, &objc));
    TRY(p11, ctx->funcs->C_FindObjectsFinal(ctx->session));

    if (objc == 0) {
        ZITI_LOG(ERROR, "key not found with given id/label");
        TRY(p11, ("not found", CKR_KEY_NEEDED));
    }

    cls = CKO_PUBLIC_KEY;
    TRY(p11, ctx->funcs->C_FindObjectsInit(ctx->session, query, qcount));
    TRY(p11, ctx->funcs->C_FindObjects(ctx->session, &p11_key->pub_handle, 1, &objc));
    TRY(p11, ctx->funcs->C_FindObjectsFinal(ctx->session));
    if (objc == 0) {
        ZITI_LOG(ERROR, "key not found with given id/label (public)");
        TRY(p11, ("public key not found", CKR_KEY_NEEDED));
    }

    CK_ULONG key_type;
    CK_ATTRIBUTE attr = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};

    TRY(p11, ctx->funcs->C_GetAttributeValue(ctx->session, p11_key->priv_handle, &attr, 1));

    switch (key_type) {
        case CKK_ECDSA:
        TRY(p11, p11_load_ecdsa(key, p11_key, &CTX));
            break;

        case CKK_RSA:
        TRY(p11, p11_load_rsa(key, p11_key, &CTX));
            break;

        default: {
            ZITI_LOG(ERROR, "only RSA and ECDSA keys are supported");
            TRY(p11, ("unsupported key type", CKR_KEY_HANDLE_INVALID));
        }
    }

    CATCH(p11) {
        free(p11_key);
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}


static int mp11_init(mp11_context *p11, const char *lib, const char *slot, const char *pin) {
    PREPCF(P11, non_zero, p11_strerror);
    memset(p11, 0, sizeof(mp11_context));

    CK_C_GetFunctionList f;
    
#if _WIN32
    //unimplemented in windows at this time
    ZITI_LOG(ERROR, "p11 not supported on Windows at this time");
    return 1;
    
    /*
    TRY(P11, (p11->lib = LoadLibrary(lib)) != NULL ? CKR_OK : CKR_LIBRARY_LOAD_FAILED);
    TRY(P11, (f = (CK_C_GetFunctionList)GetProcAddress(p11->lib, "C_GetFunctionList")) != NULL ? CKR_OK : CKR_LIBRARY_LOAD_FAILED);
    */
#else
    TRY(P11, (p11->lib = dlopen(lib, RTLD_LAZY)) != NULL ? CKR_OK : CKR_LIBRARY_LOAD_FAILED);
    TRY(P11, (f = dlsym(p11->lib, "C_GetFunctionList")) != NULL ? CKR_OK : CKR_LIBRARY_LOAD_FAILED);
#endif
    TRY(P11, f(&p11->funcs));
    TRY(P11, p11->funcs->C_Initialize(NULL));
    CK_SLOT_ID slot_id;
    if (slot == NULL || strcmp(slot, "") == 0) {
        CK_SLOT_ID_PTR slots;
        CK_ULONG slot_count;
        TRY(P11, p11->funcs->C_GetSlotList(CK_TRUE, NULL, &slot_count));
        slots = calloc(slot_count, sizeof(CK_SLOT_ID));
        TRY(P11, p11->funcs->C_GetSlotList(CK_TRUE, slots, &slot_count));
        slot_id = slots[0];
        ZITI_LOG(WARN, "slot id not specified. using the first slot[%lx] reported by driver", slot_id);
        free(slots);
    }
    else {
        slot_id = strtoul(slot, NULL, 16);
    }
    p11->slot_id = slot_id;

    TRY(P11, p11->funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &p11->session));
    TRY(P11, p11->funcs->C_Login(p11->session, CKU_USER, (uint8_t *) pin, strlen(pin)));

    CATCH(P11) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    return 0;
}

static int p11_getopt(const char *q, const char *opt, char *out, size_t maxout) {
    int optlen = strlen(opt);
    do {
        // found it
        if (strncasecmp(q, opt, optlen) == 0 && (q[optlen] == '=' || q[optlen] == 0)) {
            char *val = q + optlen + 1;
            char *end = strchr(val, '&');
            int vlen = end == NULL ? strlen(val) : end - val;
            snprintf(out, maxout, "%*.*s", vlen, vlen, val);
            return 0;

        }
        else { // skip to next '&'
            q = strchr(q, '&');
            if (q == NULL) {
                break;
            }
            q += 1;
        }
    } while (q != NULL);
    out[0] = '\0';
    return -1;
}


const char *p11_strerror(CK_RV rv) {
#define ERR_CASE(e) case e: return #e;
    switch (rv) {
        P11_ERRORS(ERR_CASE)

        default:
            return "Unexpected Error";
    }
}