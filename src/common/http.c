#include "ntc/http.h"
#include "ntc/version.h"

#include <stdio.h>
#include <string.h>

ntc_err ntc_http_format_response(ntc_arena *a, int status, const char *status_text,
                                 ntc_slice content_type, ntc_slice body,
                                 ntc_slice *out) {
    if (!a || !status_text || !out) return NTC_ERR_INVALID;

    char header[512];
    int n = snprintf(header, sizeof header,
        "HTTP/1.1 %d %s\r\n"
        "Server: " NTC_NAME "/" NTC_VERSION "\r\n"
        "Content-Type: %.*s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_text,
        (int)content_type.len, content_type.ptr,
        body.len);
    if (n < 0 || (size_t)n >= sizeof header) return NTC_ERR_OVERFLOW;

    size_t total;
    NTC_TRY(ntc_size_add((size_t)n, body.len, &total));

    char *buf = ntc_arena_alloc(a, total);
    if (!buf) return NTC_ERR_OOM;

    memcpy(buf, header, (size_t)n);
    if (body.len > 0) memcpy(buf + n, body.ptr, body.len);

    out->ptr = buf;
    out->len = total;
    return NTC_OK;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

static bool blob_contains(ntc_slice hay, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0) return true;
    if (nlen > hay.len) return false;
    for (size_t i = 0; i + nlen <= hay.len; i++)
        if (memcmp(hay.ptr + i, needle, nlen) == 0) return true;
    return false;
}

TEST(http, format_200_json) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 1024));

    ntc_slice body = NTC_SLICE_LIT("{\"ok\":true}"); /* 11 bytes */
    ntc_slice out;
    ASSERT_EQ_INT(NTC_OK, ntc_http_format_response(&a, 200, "OK",
        NTC_SLICE_LIT("application/json"), body, &out));

    ASSERT_TRUE(ntc_slice_starts_with(out, NTC_SLICE_LIT("HTTP/1.1 200 OK\r\n")));
    ASSERT_TRUE(blob_contains(out, "Content-Type: application/json"));
    ASSERT_TRUE(blob_contains(out, "Content-Length: 11"));
    ASSERT_TRUE(blob_contains(out, "Connection: close"));

    /* the body must be the exact tail of the response */
    ntc_slice tail = ntc_slice_new(out.ptr + out.len - body.len, body.len);
    ASSERT_TRUE(ntc_slice_eq(tail, body));

    ntc_arena_destroy(&a);
}

TEST(http, rejects_null_args) {
    ntc_slice out;
    ASSERT_EQ_INT(NTC_ERR_INVALID,
        ntc_http_format_response(NULL, 200, "OK",
            NTC_SLICE_LIT("text/plain"), NTC_SLICE_LIT("x"), &out));
}

TEST(http, empty_body_ok) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 512));
    ntc_slice out;
    ASSERT_EQ_INT(NTC_OK, ntc_http_format_response(&a, 204, "No Content",
        NTC_SLICE_LIT("text/plain"), NTC_SLICE_LIT(""), &out));
    ASSERT_TRUE(blob_contains(out, "Content-Length: 0"));
    ntc_arena_destroy(&a);
}
#endif /* UNIT_TEST */
