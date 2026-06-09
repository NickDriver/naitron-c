#include "ntc/builtin.h"
#include "ntc/version.h"

#include <stdio.h>

static int h_health(const ntc_request *req, const ntc_route_params *p,
                    ntc_response *res, ntc_arena *a, void *u) {
    (void)req; (void)p; (void)a; (void)u;
    res->status = 200;
    res->content_type = NTC_SLICE_LIT("application/json");
    res->body = NTC_SLICE_LIT("{\"status\":\"ok\",\"service\":\"" NTC_NAME "\"}");
    return 0;
}

static int h_version(const ntc_request *req, const ntc_route_params *p,
                     ntc_response *res, ntc_arena *a, void *u) {
    (void)req; (void)p; (void)a; (void)u;
    res->status = 200;
    res->content_type = NTC_SLICE_LIT("application/json");
    res->body = NTC_SLICE_LIT(
        "{\"name\":\"" NTC_NAME "\",\"version\":\"" NTC_VERSION "\"}");
    return 0;
}

static int h_echo(const ntc_request *req, const ntc_route_params *p,
                  ntc_response *res, ntc_arena *a, void *u) {
    (void)req; (void)u;
    ntc_slice name = ntc_params_get(p, "name");
    size_t cap = name.len + 32;
    char *buf = ntc_arena_alloc(a, cap);
    if (!buf) return -1;
    int m = snprintf(buf, cap, "{\"echo\":\"%.*s\"}", (int)name.len, name.ptr);
    if (m < 0) return -1;
    if ((size_t)m >= cap) m = (int)cap - 1;
    res->status = 200;
    res->content_type = NTC_SLICE_LIT("application/json");
    res->body = ntc_slice_new(buf, (size_t)m);
    return 0;
}

ntc_err ntc_builtin_register(ntc_router *r) {
    NTC_TRY(ntc_router_add(r, "GET", "/health", h_health, NULL));
    NTC_TRY(ntc_router_add(r, "GET", "/version", h_version, NULL));
    NTC_TRY(ntc_router_add(r, "GET", "/api/echo/:name", h_echo, NULL));
    return NTC_OK;
}
