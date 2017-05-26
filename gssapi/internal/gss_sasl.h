//+build gssapi
//+build linux darwin

#ifndef GSS_SASL_H
#define GSS_SASL_H

#include <stdlib.h>
#ifdef GOOS_linux
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif
#ifdef GOOS_darwin
#include <GSS/GSS.h>
#endif

#define GSSAPI_OK 0
#define GSSAPI_CONTINUE 1
#define GSSAPI_ERROR 2

int gssapi_acquire_cred(
    OM_uint32* major_status,
    OM_uint32* minor_status,
    char* username,
    char* password,
    gss_OID name_type,
    gss_cred_usage_t cred_usage,
    gss_cred_id_t* output_cred
);

int gssapi_delete_sec_context(
    gss_ctx_id_t* ctx
);

int gssapi_display_name(
    OM_uint32* major_status,
    OM_uint32* minor_status,
    gss_cred_id_t cred,
    char** output_name
);

int gssapi_error_desc(
    OM_uint32 major_status, 
    OM_uint32 minor_status, 
    char **output_desc
);

int gssapi_init_sec_context(
    OM_uint32* major_status,
    OM_uint32* minor_status,
    gss_cred_id_t cred,
    gss_ctx_id_t* ctx,
    char* spn,
    OM_uint32 flags,                    
    void* input,
    size_t input_length,
    void** output,
    size_t* output_length
);

int gssapi_release_cred(
    gss_cred_id_t* cred
);

int gssapi_wrap_msg(
    OM_uint32* major_status,
    OM_uint32* minor_status,
    gss_ctx_id_t ctx,
    void* input,
    size_t input_length,
    void** output,
    size_t* output_length 
);

#endif // GSS_SASL_H