#include "ntc/http.h"
#include "ntc/version.h"

#include <stdio.h>
#include <string.h>

const char *ntc_http_status_text(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:  return "OK";
    }
}

ntc_err ntc_http_format_response(ntc_arena *a, int status, const char *status_text,
                                 ntc_slice content_type, ntc_slice body,
                                 ntc_slice *out) {
    return ntc_http_format_response_ex(a, status, status_text, content_type, NULL, body, out);
}

ntc_err ntc_http_format_response_ex(ntc_arena *a, int status, const char *status_text,
                                    ntc_slice content_type, const char *extra_headers,
                                    ntc_slice body, ntc_slice *out) {
    if (!a || !status_text || !out) return NTC_ERR_INVALID;

    char header[1024];
    int n = snprintf(header, sizeof header,
        "HTTP/1.1 %d %s\r\n"
        "Server: " NTC_NAME "/" NTC_VERSION "\r\n"
        "Content-Type: %.*s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status, status_text,
        (int)content_type.len, content_type.ptr,
        body.len,
        extra_headers ? extra_headers : "");
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

ntc_err ntc_http_format_stream_head(ntc_arena *a, int status, const char *status_text,
                                    ntc_slice content_type, bool sse,
                                    const char *extra_headers, ntc_slice *out) {
    if (!a || !status_text || !out) return NTC_ERR_INVALID;

    char header[1024];
    int n;
    if (sse) {
        /* SSE: raw passthrough, no Content-Length, ended by close. */
        n = snprintf(header, sizeof header,
            "HTTP/1.1 %d %s\r\n"
            "Server: " NTC_NAME "/" NTC_VERSION "\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n"
            "%s"
            "\r\n",
            status, status_text, extra_headers ? extra_headers : "");
    } else {
        n = snprintf(header, sizeof header,
            "HTTP/1.1 %d %s\r\n"
            "Server: " NTC_NAME "/" NTC_VERSION "\r\n"
            "Content-Type: %.*s\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "%s"
            "\r\n",
            status, status_text,
            (int)content_type.len, content_type.ptr,
            extra_headers ? extra_headers : "");
    }
    if (n < 0 || (size_t)n >= sizeof header) return NTC_ERR_OVERFLOW;

    char *buf = ntc_arena_alloc(a, (size_t)n);
    if (!buf) return NTC_ERR_OOM;
    memcpy(buf, header, (size_t)n);
    out->ptr = buf;
    out->len = (size_t)n;
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

TEST(http, stream_head_sse) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 1024));
    ntc_slice out;
    ASSERT_EQ_INT(NTC_OK, ntc_http_format_stream_head(&a, 200, "OK",
        NTC_SLICE_LIT("ignored"), true, "X-Request-Id: abc\r\n", &out));
    ASSERT_TRUE(ntc_slice_starts_with(out, NTC_SLICE_LIT("HTTP/1.1 200 OK\r\n")));
    ASSERT_TRUE(blob_contains(out, "Content-Type: text/event-stream"));
    ASSERT_TRUE(blob_contains(out, "Cache-Control: no-cache"));
    ASSERT_TRUE(blob_contains(out, "X-Request-Id: abc"));
    ASSERT_FALSE(blob_contains(out, "Content-Length"));
    /* ends with the blank line, no body */
    ASSERT_TRUE(out.len >= 4 && memcmp(out.ptr + out.len - 4, "\r\n\r\n", 4) == 0);
    ntc_arena_destroy(&a);
}

TEST(http, stream_head_chunked) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 1024));
    ntc_slice out;
    ASSERT_EQ_INT(NTC_OK, ntc_http_format_stream_head(&a, 200, "OK",
        NTC_SLICE_LIT("application/json"), false, NULL, &out));
    ASSERT_TRUE(blob_contains(out, "Content-Type: application/json"));
    ASSERT_TRUE(blob_contains(out, "Transfer-Encoding: chunked"));
    ASSERT_FALSE(blob_contains(out, "Content-Length"));
    ntc_arena_destroy(&a);
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
