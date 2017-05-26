//+build gssapi
//+build linux darwin

#include <string.h>
#include "gss_sasl.h"

OM_uint32 gssapi_canonicalize_name(
    OM_uint32* minor_status, 
    char* input_name, 
    gss_OID input_name_type, 
    gss_name_t *output_name
)
{
    OM_uint32 major_status;
    gss_name_t imported_name = GSS_C_NO_NAME;
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;

    buffer.value = input_name;
    buffer.length = strlen(input_name);
    major_status = gss_import_name(minor_status, &buffer, input_name_type, &imported_name);
    if (GSS_ERROR(major_status)) {
        return major_status;
    }

    major_status = gss_canonicalize_name(minor_status, imported_name, (gss_OID)gss_mech_krb5, output_name);
    if (imported_name != GSS_C_NO_NAME) {
        OM_uint32 ignored;
        gss_release_name(&ignored, &imported_name);
    }

    return major_status;
}

int gssapi_acquire_cred(
    OM_uint32* major_status,
    OM_uint32* minor_status,
    char* username,
    char* password,
    gss_OID name_type,
    gss_cred_usage_t cred_usage,
    gss_cred_id_t* output_cred
)
{
    if (username) {
        gss_name_t name;
        *major_status = gssapi_canonicalize_name(minor_status, username, name_type, &name);
        if (GSS_ERROR(*major_status)) {
            return GSSAPI_ERROR;
        }

        if (password) {
            gss_buffer_desc password_buffer;
            password_buffer.value = password;
            password_buffer.length = strlen(password);
            *major_status = gss_acquire_cred_with_password(minor_status, name, &password_buffer, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, cred_usage, output_cred, NULL, NULL);
        } else {
            *major_status = gss_acquire_cred(minor_status, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, cred_usage, output_cred, NULL, NULL);
        }

        OM_uint32 ignored;
        gss_release_name(&ignored, &name);

        if (GSS_ERROR(*major_status)) {
            return GSSAPI_ERROR;
        }
    } else {
        *output_cred = GSS_C_NO_CREDENTIAL;
    }

    return GSSAPI_OK;
}

int gssapi_display_name(
    OM_uint32* major_status,
    OM_uint32* minor_status,
    gss_cred_id_t cred,
    char** output_name
)
{
    OM_uint32 ignore;
    gss_name_t name = GSS_C_NO_NAME;

    *major_status = gss_inquire_cred(minor_status, cred, &name, NULL, NULL, NULL);
    if (GSS_ERROR(*major_status)) {
        return GSSAPI_ERROR;
    }

    gss_buffer_desc name_buffer;
    *major_status = gss_display_name(minor_status, name, &name_buffer, NULL);
    gss_release_name(&ignore, &name);

    if (GSS_ERROR(*major_status)) {
        return GSSAPI_ERROR;
    }

    if (name_buffer.length) {
        *output_name = malloc(name_buffer.length+1); 
        memcpy(*output_name, name_buffer.value, name_buffer.length+1);

        gss_release_buffer(&ignore, &name_buffer);
    }

    return GSSAPI_OK;
}

int gssapi_error_desc(
    OM_uint32 major_status, 
    OM_uint32 minor_status, 
    char **output_desc
)
{
    OM_uint32 status = major_status;
    int status_type = GSS_C_GSS_CODE;
    if (minor_status != 0) {
        status = minor_status;
        status_type = GSS_C_MECH_CODE;
    }

    OM_uint32 local_major_status, local_minor_status;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc desc_buffer;
    do
    {
        local_major_status = gss_display_status(
            &local_minor_status,
            status,
            status_type,
            GSS_C_NO_OID,
            &msg_ctx,
            &desc_buffer
        );
        if (GSS_ERROR(local_major_status)) {
            return GSSAPI_ERROR;
        }

        if (*output_desc) {
            free(*output_desc);
        }

        *output_desc = malloc(desc_buffer.length+1);
        memcpy(*output_desc, desc_buffer.value, desc_buffer.length+1);

        gss_release_buffer(&local_minor_status, &desc_buffer);
    }
    while(msg_ctx != 0);

    return GSSAPI_OK;
}

int gssapi_delete_sec_context(
    gss_ctx_id_t* ctx
)
{
    OM_uint32 ignored;
    if (*ctx != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&ignored, ctx, GSS_C_NO_BUFFER);
    }

    return GSSAPI_OK;
}

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
)
{
    gss_buffer_desc input_buffer = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_buffer = GSS_C_EMPTY_BUFFER;

    if (input) {
        input_buffer.value = input;
        input_buffer.length = input_length;
    }

    gss_name_t spn_name;
    *major_status = gssapi_canonicalize_name(minor_status, spn, GSS_C_NT_HOSTBASED_SERVICE, &spn_name);
    if (GSS_ERROR(*major_status)) {
        return GSSAPI_ERROR;
    }

    *major_status = gss_init_sec_context(
        minor_status,
        cred,
        ctx,
        spn_name,
        GSS_C_NO_OID,
        flags,
        0,
        GSS_C_NO_CHANNEL_BINDINGS,
        &input_buffer,
        NULL,
        &output_buffer,
        NULL,
        NULL
    );

    OM_uint32 ignored;
    gss_release_name(&ignored, &spn_name);

    if (output_buffer.length) {
        *output = malloc(output_buffer.length);
        *output_length = output_buffer.length;
        memcpy(*output, output_buffer.value, output_buffer.length);

        gss_release_buffer(&ignored, &output_buffer);
    }

    if (GSS_ERROR(*major_status)) {
        return GSSAPI_ERROR;
    } else if (*major_status == GSS_S_CONTINUE_NEEDED) {
        return GSSAPI_CONTINUE;
    }

    return GSSAPI_OK;
}

int gssapi_release_cred(
    gss_cred_id_t* cred
)
{
    OM_uint32 ignored;
    if (*cred != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&ignored, cred);
    }
}

int gssapi_wrap_msg(
    OM_uint32* major_status,
    OM_uint32* minor_status,
    gss_ctx_id_t ctx,
    void* input,
    size_t input_length,
    void** output,
    size_t* output_length 
)
{
    gss_buffer_desc input_buffer = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_buffer = GSS_C_EMPTY_BUFFER;

    input_buffer.value = input;
    input_buffer.length = input_length;

    *major_status = gss_wrap(minor_status, ctx, 0, GSS_C_QOP_DEFAULT, &input_buffer, NULL, &output_buffer);

    if (output_buffer.length) {
        *output = malloc(output_buffer.length);
        *output_length = output_buffer.length;
        memcpy(*output, output_buffer.value, output_buffer.length);

        OM_uint32 ignored;
        gss_release_buffer(&ignored, &output_buffer);
    }

    if(GSS_ERROR(*major_status)) {
        return GSSAPI_ERROR;
    }

    return GSSAPI_OK;
}