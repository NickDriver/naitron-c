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
    /* ?redirect=<url> exercises controller-set headers (302 + Location + custom) */
    ntc_slice rd = ntc_req_query(req, "redirect");
    if (rd.len && rd.len < 240) {
        char loc[256];
        snprintf(loc, sizeof loc, "%.*s", (int)rd.len, rd.ptr);
        ntc_res_header(res, "X-Test", "hello");
        return ntc_redirect(res, 302, loc);
    }
    ntc_slice name = ntc_req_param(req, "name");   /* path param :name  */
    ntc_slice sub = req->auth_sub;                 /* auth subject      */
    return ntc_reply_json(res, a, 200,
        "{\"controller\":\"hello\",\"pid\":%ld,\"method\":\"%.*s\",\"path\":\"%.*s\","
        "\"name\":\"%.*s\",\"sub\":\"%.*s\"}",
        (long)getpid(),
        (int)req->method.len, req->method.ptr,
        (int)req->path.len, req->path.ptr,
        (int)name.len, name.ptr,
        (int)sub.len, sub.ptr);
}

int main(void) {
    ntc_controller ctl = { .name = "hello", .handle = handle, .udata = NULL };
    return ntc_controller_run(&ctl);
}
