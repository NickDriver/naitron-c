/* upload_echo.c - example multipart/form-data controller.
 *
 * Parses a multipart upload (the SDK's ntc_multipart_* helpers) and echoes a
 * summary: how many parts, the "field" text value, and the "file" part's
 * filename + size. The body crosses the wire as one blob; parsing is the
 * controller's job. */
#define _GNU_SOURCE
#include "ntc/controller.h"
#include "ntc/http.h"

#include <stdio.h>
#include <string.h>

static int handle(const ntc_request *req, ntc_response *res, ntc_arena *a, void *u) {
    (void)u;
    char boundary[128];
    if (!ntc_multipart_boundary(ntc_http_header(req, "content-type"), boundary, sizeof boundary))
        return ntc_reply_json(res, a, 400, "{\"error\":\"not multipart/form-data\"}");

    ntc_multipart_part parts[16];
    int n = ntc_multipart_parse(req->body, boundary, parts, 16);
    if (n < 0) return ntc_reply_json(res, a, 400, "{\"error\":\"malformed multipart\"}");

    ntc_slice field = ntc_slice_new("", 0), fname = ntc_slice_new("", 0);
    size_t fsize = 0;
    for (int i = 0; i < n; i++) {
        if (ntc_slice_eq_cstr(parts[i].name, "field")) field = parts[i].data;
        if (ntc_slice_eq_cstr(parts[i].name, "file")) { fname = parts[i].filename; fsize = parts[i].data.len; }
    }
    return ntc_reply_json(res, a, 200,
        "{\"parts\":%d,\"field\":\"%.*s\",\"filename\":\"%.*s\",\"filesize\":%zu}",
        n, (int)field.len, field.ptr, (int)fname.len, fname.ptr, fsize);
}

int main(void) {
    ntc_controller ctl = { .name = "upload", .handle = handle, .udata = NULL };
    return ntc_controller_run(&ctl);
}
