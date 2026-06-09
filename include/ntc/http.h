/* http.h - HTTP/1.1 request parsing + response serialization. */
#ifndef NTC_HTTP_H
#define NTC_HTTP_H

#include <stdbool.h>
#include <stddef.h>

#include "ntc/arena.h"
#include "ntc/err.h"
#include "ntc/slice.h"

#define NTC_MAX_HEADERS 64

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
    bool has_content_length;
    size_t content_length;
    ntc_slice body;            /* body bytes present in buf  */
} ntc_request;

typedef enum ntc_parse_result {
    NTC_PARSE_OK,         /* request line + headers fully parsed */
    NTC_PARSE_INCOMPLETE, /* need more bytes (no end-of-headers yet) */
    NTC_PARSE_ERROR       /* malformed */
} ntc_parse_result;

/* Parse a request from buf[0..len). Slices point into buf (zero-copy), so buf
 * must outlive `req`. On OK, *consumed = bytes through the end of headers, and
 * req->body is whatever body bytes are already in buf (compare to
 * content_length to know if more must be read). */
ntc_parse_result ntc_http_parse_request(const char *buf, size_t len,
                                        ntc_request *req, size_t *consumed);

/* Case-insensitive header lookup; returns the value slice or an empty slice. */
ntc_slice ntc_http_header(const ntc_request *req, const char *name);

/* Standard reason phrase for a status code (e.g. 404 -> "Not Found"). */
const char *ntc_http_status_text(int status);

/* Format a complete HTTP/1.1 response into `a` (Connection: close). */
NTC_NODISCARD ntc_err ntc_http_format_response(ntc_arena *a, int status,
        const char *status_text, ntc_slice content_type, ntc_slice body,
        ntc_slice *out);

#endif /* NTC_HTTP_H */
