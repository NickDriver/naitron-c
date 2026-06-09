/* hello_controller.c - example out-of-process controller using the SDK.
 *
 * Built as its own binary. The core spawns it and forwards routed requests over
 * the IPC socket; this code never sees the wire protocol. */
#define _GNU_SOURCE /* getpid under -std=c23 on Linux */
#include "ntc/controller.h"

#include <stdio.h>
#include <unistd.h>

static int handle(const ntc_request *req, ntc_response *res, ntc_arena *a, void *u) {
    (void)u;
    size_t cap = req->method.len + req->path.len + 160;
    char *body = ntc_arena_alloc(a, cap);
    if (!body) return -1;
    int m = snprintf(body, cap,
        "{\"controller\":\"hello\",\"pid\":%ld,\"method\":\"%.*s\",\"path\":\"%.*s\"}",
        (long)getpid(),
        (int)req->method.len, req->method.ptr,
        (int)req->path.len, req->path.ptr);
    if (m < 0) return -1;
    if ((size_t)m >= cap) m = (int)cap - 1;
    res->status = 200;
    res->content_type = NTC_SLICE_LIT("application/json");
    res->body = ntc_slice_new(body, (size_t)m);
    return 0;
}

int main(void) {
    ntc_controller ctl = { .name = "hello", .handle = handle, .udata = NULL };
    return ntc_controller_run(&ctl);
}
