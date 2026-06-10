/* http.h - HTTP/1.1 request parsing + response serialization. */
#ifndef NTC_HTTP_H
#define NTC_HTTP_H

#include <stdbool.h>
#include <stddef.h>

#include "ntc/arena.h"
#include "ntc/err.h"
#include "ntc/slice.h"

#define NTC_MAX_HEADERS 64
#define NTC_MAX_PARAMS  8

typedef struct ntc_header {
    ntc_slice name;
    ntc_slice value;
} ntc_header;

typedef struct ntc_request {
    ntc_slice method;          /* "GET"                      */
    ntc_slice target;          /* "/api/users?x=1"           */
    ntc_slice path;            /* "/api/users"               */
    ntc_slice query;           /* "x=1" (no '?')             */
    int minor_version;         /* 0 or 1 for HTTP/1.x        */
    ntc_header headers[NTC_MAX_HEADERS];
    size_t nheaders;
    ntc_header params[NTC_MAX_PARAMS]; /* captured path params (controller side) */
    size_t nparams;
    ntc_slice auth_sub;        /* authenticated subject ("" if none) */
    ntc_slice auth_scope;
    bool has_content_length;
    size_t content_length;
    ntc_slice body;            /* body bytes present in buf  */
} ntc_request;

typedef enum ntc_parse_result {
    NTC_PARSE_OK,         /* request line + headers fully parsed */
    NTC_PARSE_INCOMPLETE, /* need more bytes (no end-of-headers yet) */
    NTC_PARSE_ERROR       /* malformed */
} ntc_parse_result;

/* What a controller fills in; body is allocated in the request arena. */
typedef struct ntc_response {
    int status;
    ntc_slice content_type;
    ntc_slice body;
} ntc_response;

/* Parse a request from buf[0..len). Slices point into buf (zero-copy), so buf
 * must outlive `req`. On OK, *consumed = bytes through the end of headers, and
 * req->body is whatever body bytes are already in buf (compare to
 * content_length to know if more must be read). */
ntc_parse_result ntc_http_parse_request(const char *buf, size_t len,
                                        ntc_request *req, size_t *consumed);

/* Case-insensitive header lookup; returns the value slice or an empty slice. */
ntc_slice ntc_http_header(const ntc_request *req, const char *name);

/* Controller-side accessors. */
ntc_slice ntc_req_param(const ntc_request *req, const char *name); /* path param */
ntc_slice ntc_req_query(const ntc_request *req, const char *name); /* ?k=v (raw) */

/* Standard reason phrase for a status code (e.g. 404 -> "Not Found"). */
const char *ntc_http_status_text(int status);

/* Format a complete HTTP/1.1 response into `a` (Connection: close). */
NTC_NODISCARD ntc_err ntc_http_format_response(ntc_arena *a, int status,
        const char *status_text, ntc_slice content_type, ntc_slice body,
        ntc_slice *out);

/* Like the above, plus `extra_headers` (complete "Name: value\r\n" lines, or
 * NULL) inserted before the blank line - for middleware-added headers. */
NTC_NODISCARD ntc_err ntc_http_format_response_ex(ntc_arena *a, int status,
        const char *status_text, ntc_slice content_type, const char *extra_headers,
        ntc_slice body, ntc_slice *out);

/* Format the HEAD of a streamed response (no body, no Content-Length). If `sse`
 * is true: Content-Type: text/event-stream + Cache-Control: no-cache (raw
 * passthrough). Otherwise: Transfer-Encoding: chunked with the given
 * content_type. Connection: close in both. Body chunks follow separately. */
NTC_NODISCARD ntc_err ntc_http_format_stream_head(ntc_arena *a, int status,
        const char *status_text, ntc_slice content_type, bool sse,
        const char *extra_headers, ntc_slice *out);

#endif /* NTC_HTTP_H */
