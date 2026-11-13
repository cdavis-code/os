/* SPDX-License-Identifier: MIT
 * Bounded behavior tests. Allocator interposition is test-only and requires
 * glibc. No network traffic, real credentials, or resource exhaustion.
 */
#define _GNU_SOURCE
#define GSSRPC__IMPL
#include "k5-int.h"
#include <gssrpc/rpc.h>
#include <gssrpc/auth_gssapi.h>
#include <gssrpc/svc_auth.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static int observing;
static size_t growth_calls, array_allocations;
static void *live[256];
static void *watched_token;
static unsigned token_frees;
static unsigned char argument_wire[64];
static unsigned argument_length;

static int slot(void *ptr)
{
    unsigned i;
    for (i = 0; i < 256; i++)
        if (live[i] == ptr)
            return (int)i;
    return -1;
}

static void remember(void *ptr)
{
    int i;
    if (!observing || ptr == NULL)
        return;
    i = slot(NULL);
    if (i < 0)
        _Exit(2); /* Instrumentation limit, never an expected regression. */
    live[i] = ptr;
}

void *malloc(size_t n)
{
    void *ptr = __libc_malloc(n);
    remember(ptr);
    return ptr;
}

void *calloc(size_t n, size_t size)
{
    void *ptr = __libc_calloc(n, size);
    if (observing && n * size == 32 * sizeof(krb5_enctype))
        array_allocations++;
    remember(ptr);
    return ptr;
}

void *realloc(void *old, size_t size)
{
    int i = observing && old != NULL ? slot(old) : -1;
    void *ptr = __libc_realloc(old, size);
    if (observing) {
        growth_calls++;
        if (ptr != NULL) {
            if (i >= 0)
                live[i] = ptr;
            else if (old == NULL)
                remember(ptr);
        }
    }
    return ptr;
}

void free(void *ptr)
{
    int i;
    if (ptr != NULL && ptr == watched_token) {
        token_frees++;
        watched_token = NULL;
    }
    if (observing && ptr != NULL && (i = slot(ptr)) >= 0)
        live[i] = NULL;
    __libc_free(ptr);
}

static bool_t getargs(SVCXPRT *transport, xdrproc_t proc, void *argument)
{
    XDR stream;
    bool_t result;
    (void)transport;
    xdrmem_create(&stream, (char *)argument_wire, argument_length, XDR_DECODE);
    result = proc(&stream, argument);
    watched_token = ((auth_gssapi_init_arg *)argument)->token.value;
    XDR_DESTROY(&stream);
    return result;
}

static int default_rejection(void)
{
    SVCXPRT transport = {0};
    struct svc_req request = {0};
    struct rpc_msg message = {0};
    bool_t no_dispatch = FALSE;
    enum auth_stat result;
    unsetenv("GSSRPC_ALLOW_AUTH_GSSAPI");
    request.rq_xprt = &transport;
    result = gssrpc__svcauth_gssapi(&request, &message, &no_dispatch);
    printf("default rejection: auth_stat=%d expected=%d\n", result, AUTH_REJECTEDCRED);
    return result != AUTH_REJECTEDCRED;
}

static int cleanup_case(int truncated)
{
    SVCXPRT transport = {0};
    struct xp_ops operations = {0};
    struct svc_req request = {0};
    struct rpc_msg message = {0};
    auth_gssapi_creds credentials = {2, TRUE, {0, NULL}};
    char credentials_wire[64], token[16] = {0};
    auth_gssapi_init_arg argument = {99, {sizeof(token), token}};
    XDR stream;
    bool_t no_dispatch = FALSE;
    enum auth_stat result;
    int failed;
    xdrmem_create(&stream, credentials_wire, sizeof(credentials_wire), XDR_ENCODE);
    if (!xdr_authgssapi_creds(&stream, &credentials))
        return 2;
    message.rm_call.cb_cred.oa_length = XDR_GETPOS(&stream);
    message.rm_call.cb_cred.oa_base = credentials_wire;
    message.rm_call.cb_cred.oa_flavor = AUTH_GSSAPI;
    XDR_DESTROY(&stream);
    xdrmem_create(&stream, (char *)argument_wire, sizeof(argument_wire), XDR_ENCODE);
    if (!xdr_authgssapi_init_arg(&stream, &argument))
        return 2;
    argument_length = XDR_GETPOS(&stream) - (truncated ? 4 : 0);
    XDR_DESTROY(&stream);
    operations.xp_getargs = getargs;
    transport.xp_ops = &operations;
    request.rq_xprt = &transport;
    request.rq_proc = AUTH_GSSAPI_INIT;
    watched_token = NULL;
    token_frees = 0;
    if (setenv("GSSRPC_ALLOW_AUTH_GSSAPI", "yes", 1) != 0)
        return 2;
    result = gssrpc__svcauth_gssapi(&request, &message, &no_dispatch);
    failed = result != AUTH_BADCRED || token_frees != 1;
    printf("cleanup %s: auth_stat=%d token_frees=%u expected=1\n",
           truncated ? "partial decode" : "invalid version", result, token_frees);
    /* Bound the vulnerable baseline's deliberate single-buffer leak. */
    if (watched_token != NULL)
        free(watched_token);
    return failed;
}

static int single_allocation(void)
{
    unsigned char wire[98] = {0x30, 96};
    krb5_data data = {0};
    krb5_etype_list *decoded = NULL;
    krb5_error_code result;
    unsigned i;
    int failed = 0, retained = 0;
    for (i = 0; i < 32; i++) {
        wire[2 + 3 * i] = 0x02;
        wire[3 + 3 * i] = 0x01;
        wire[4 + 3 * i] = 18;
    }
    data.data = (char *)wire;
    data.length = sizeof(wire);
    observing = 1;
    result = decode_krb5_etype_list(&data, &decoded);
    observing = 0;
    if (result != 0 || decoded == NULL || decoded->length != 32)
        return 2;
    for (i = 0; i < 32; i++)
        failed |= decoded->etypes[i] != 18;
    printf("ASN.1 valid sequence: realloc_calls=%zu array_allocations=%zu expected=0,1\n",
           growth_calls, array_allocations);
    failed |= growth_calls != 0 || array_allocations != 1;
    observing = 1;
    free(decoded->etypes);
    free(decoded);
    observing = 0;
    for (i = 0; i < 256; i++)
        failed |= live[i] != NULL;

    /* One wrong final tag: bounded rejection and no retained allocations. */
    wire[95] = 0x04;
    decoded = NULL;
    growth_calls = array_allocations = 0;
    observing = 1;
    result = decode_krb5_etype_list(&data, &decoded);
    observing = 0;
    failed |= result == 0 || decoded != NULL;
    for (i = 0; i < 256; i++)
        retained |= live[i] != NULL;
    failed |= retained || growth_calls != 0 || array_allocations != 0;
    printf("ASN.1 malformed sequence: rejected=%d retained=%d realloc_calls=%zu array_allocations=%zu\n",
           result != 0, retained, growth_calls, array_allocations);
    return failed;
}

int main(int argc, char **argv)
{
    Dl_info library;
    int first, second;
    if (argc != 2)
        return 2;
    if (!dladdr((void *)gssrpc__svcauth_gssapi, &library))
        return 2;
    printf("loaded RPC library: %s\n", library.dli_fname);
    if (!dladdr((void *)decode_krb5_etype_list, &library))
        return 2;
    printf("loaded ASN.1 library: %s\n", library.dli_fname);
    if (strcmp(argv[1], "auth_default_rejection") == 0)
        return default_rejection();
    if (strcmp(argv[1], "auth_cleanup") == 0) {
        first = cleanup_case(0);
        second = cleanup_case(1);
        return first == 2 || second == 2 ? 2 : first || second;
    }
    if (strcmp(argv[1], "asn1_single_allocation") == 0)
        return single_allocation();
    return 2;
}
