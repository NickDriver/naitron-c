#include "ntc/http.h"

#include <string.h>

#define NTC_MAX_HEADER_BYTES (32 * 1024)

static const char *find_crlf(const char *s, const char *end) {
    for (const char *p = s; p + 1 < end; p++)
        if (p[0] == '\r' && p[1] == '\n') return p;
    return NULL;
}

static const char *find_eoh(const char *buf, size_t len) {
    for (size_t i = 0; i + 4 <= len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return buf + i;
    return NULL;
}

static char lc(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static bool islabel_eq(ntc_slice a, const char *b) {
    size_t n = strlen(b);
    if (a.len != n) return false;
    for (size_t i = 0; i < n; i++)
        if (lc(a.ptr[i]) != lc(b[i])) return false;
    return true;
}

static bool is_tchar(char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9'))
        return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~': return true;
        default: return false;
    }
}

static bool is_token(ntc_slice s) {
    if (s.len == 0) return false;
    for (size_t i = 0; i < s.len; i++)
        if (!is_tchar(s.ptr[i])) return false;
    return true;
}

ntc_parse_result ntc_http_parse_request(const char *buf, size_t len,
                                        ntc_request *req, size_t *consumed) {
    if (!buf || !req || !consumed) return NTC_PARSE_ERROR;

    const char *eoh = find_eoh(buf, len);
    if (!eoh) {
        if (len > NTC_MAX_HEADER_BYTES) return NTC_PARSE_ERROR; /* -> 431 */
        return NTC_PARSE_INCOMPLETE;
    }

    memset(req, 0, sizeof *req);
    *consumed = (size_t)(eoh + 4 - buf);

    /* ---- request line: METHOD SP target SP HTTP/1.x ---- */
    const char *rl = find_crlf(buf, eoh + 2);
    if (!rl) return NTC_PARSE_ERROR;

    const char *sp1 = memchr(buf, ' ', (size_t)(rl - buf));
    if (!sp1) return NTC_PARSE_ERROR;
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(rl - (sp1 + 1)));
    if (!sp2) return NTC_PARSE_ERROR;

    req->method = ntc_slice_new(buf, (size_t)(sp1 - buf));
    req->target = ntc_slice_new(sp1 + 1, (size_t)(sp2 - (sp1 + 1)));
    ntc_slice version = ntc_slice_new(sp2 + 1, (size_t)(rl - (sp2 + 1)));

    if (!is_token(req->method)) return NTC_PARSE_ERROR;
    if (req->target.len == 0) return NTC_PARSE_ERROR;
    if (version.len != 8 || memcmp(version.ptr, "HTTP/1.", 7) != 0)
        return NTC_PARSE_ERROR;
    if (version.ptr[7] != '0' && version.ptr[7] != '1') return NTC_PARSE_ERROR;
    req->minor_version = version.ptr[7] - '0';

    const char *q = memchr(req->target.ptr, '?', req->target.len);
    if (q) {
        req->path = ntc_slice_new(req->target.ptr, (size_t)(q - req->target.ptr));
        req->query = ntc_slice_new(q + 1,
            req->target.len - (size_t)(q - req->target.ptr) - 1);
    } else {
        req->path = req->target;
        req->query = ntc_slice_new(req->target.ptr + req->target.len, 0);
    }

    /* ---- headers ---- */
    const char *cur = rl + 2;
    while (cur < eoh) {
        const char *le = find_crlf(cur, eoh + 2);
        if (!le) return NTC_PARSE_ERROR;

        const char *colon = memchr(cur, ':', (size_t)(le - cur));
        if (!colon) return NTC_PARSE_ERROR;

        ntc_slice name = ntc_slice_new(cur, (size_t)(colon - cur));
        ntc_slice value = ntc_slice_trim(
            ntc_slice_new(colon + 1, (size_t)(le - (colon + 1))));
        if (!is_token(name)) return NTC_PARSE_ERROR;
        if (req->nheaders >= NTC_MAX_HEADERS) return NTC_PARSE_ERROR;

        req->headers[req->nheaders].name = name;
        req->headers[req->nheaders].value = value;
        req->nheaders++;

        if (islabel_eq(name, "content-length")) {
            if (value.len == 0) return NTC_PARSE_ERROR;
            size_t cl = 0;
            for (size_t i = 0; i < value.len; i++) {
                char ch = value.ptr[i];
                if (ch < '0' || ch > '9') return NTC_PARSE_ERROR;
                if (ntc_size_mul(cl, 10, &cl) != NTC_OK) return NTC_PARSE_ERROR;
                if (ntc_size_add(cl, (size_t)(ch - '0'), &cl) != NTC_OK)
                    return NTC_PARSE_ERROR;
            }
            if (req->has_content_length && req->content_length != cl)
                return NTC_PARSE_ERROR; /* conflicting CL: smuggling guard */
            req->has_content_length = true;
            req->content_length = cl;
        }
        cur = le + 2;
    }

    req->body = ntc_slice_new(buf + *consumed, len - *consumed);
    return NTC_PARSE_OK;
}

ntc_slice ntc_http_header(const ntc_request *req, const char *name) {
    for (size_t i = 0; i < req->nheaders; i++)
        if (islabel_eq(req->headers[i].name, name))
            return req->headers[i].value;
    return ntc_slice_new(NULL, 0);
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(http_parse, simple_get) {
    const char *r = "GET /api/hello HTTP/1.1\r\nHost: x\r\n\r\n";
    ntc_request req;
    size_t consumed = 0;
    ASSERT_EQ_INT(NTC_PARSE_OK,
                  ntc_http_parse_request(r, strlen(r), &req, &consumed));
    ASSERT_TRUE(ntc_slice_eq_cstr(req.method, "GET"));
    ASSERT_TRUE(ntc_slice_eq_cstr(req.path, "/api/hello"));
    ASSERT_EQ_UINT(0u, req.query.len);
    ASSERT_EQ_INT(1, req.minor_version);
    ASSERT_EQ_UINT(1u, req.nheaders);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_http_header(&req, "host"), "x"));
    ASSERT_EQ_UINT(strlen(r), consumed);
}

TEST(http_parse, query_string_split) {
    const char *r = "GET /search?q=cats&p=2 HTTP/1.1\r\n\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_OK, ntc_http_parse_request(r, strlen(r), &req, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(req.path, "/search"));
    ASSERT_TRUE(ntc_slice_eq_cstr(req.query, "q=cats&p=2"));
    ASSERT_EQ_UINT(0u, req.nheaders);
}

TEST(http_parse, post_with_body) {
    const char *r = "POST /u HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_OK, ntc_http_parse_request(r, strlen(r), &req, &c));
    ASSERT_TRUE(req.has_content_length);
    ASSERT_EQ_UINT(5u, req.content_length);
    ASSERT_TRUE(ntc_slice_eq_cstr(req.body, "hello"));
}

TEST(http_parse, header_lookup_case_insensitive) {
    const char *r = "GET / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_OK, ntc_http_parse_request(r, strlen(r), &req, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_http_header(&req, "CONTENT-TYPE"),
                                  "application/json"));
    ASSERT_EQ_UINT(0u, ntc_http_header(&req, "missing").len);
}

TEST(http_parse, incomplete_without_eoh) {
    const char *r = "GET / HTTP/1.1\r\nHost: x\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_INCOMPLETE,
                  ntc_http_parse_request(r, strlen(r), &req, &c));
}

TEST(http_parse, rejects_bad_version) {
    const char *r = "GET / HTTP/2.0\r\n\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_ERROR, ntc_http_parse_request(r, strlen(r), &req, &c));
}

TEST(http_parse, rejects_missing_target) {
    const char *r = "GET  HTTP/1.1\r\n\r\n"; /* two spaces -> empty target */
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_ERROR, ntc_http_parse_request(r, strlen(r), &req, &c));
}

TEST(http_parse, rejects_header_without_colon) {
    const char *r = "GET / HTTP/1.1\r\nBadHeaderLine\r\n\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_ERROR, ntc_http_parse_request(r, strlen(r), &req, &c));
}

TEST(http_parse, rejects_conflicting_content_length) {
    const char *r = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_ERROR, ntc_http_parse_request(r, strlen(r), &req, &c));
}

TEST(http_parse, rejects_nondigit_content_length) {
    const char *r = "POST / HTTP/1.1\r\nContent-Length: 12x\r\n\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_ERROR, ntc_http_parse_request(r, strlen(r), &req, &c));
}

TEST(http_parse, duplicate_content_length_same_value_ok) {
    const char *r = "POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
    ntc_request req; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_OK, ntc_http_parse_request(r, strlen(r), &req, &c));
    ASSERT_EQ_UINT(0u, req.content_length);
}
#endif /* UNIT_TEST */
