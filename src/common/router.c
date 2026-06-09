#include "ntc/router.h"

#include <stdlib.h>
#include <string.h>

#define NTC_MAX_SEGMENTS 16

typedef struct {
    ntc_slice s;     /* segment text (param name has the ':' stripped) */
    bool is_param;
} seg_t;

typedef struct {
    char *method;
    char *pattern;
    seg_t segs[NTC_MAX_SEGMENTS];
    size_t nsegs;
    ntc_handler handler;
    void *udata;
} route_t;

struct ntc_router {
    route_t *routes;
    size_t count, cap;
};

static char *dup_str(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

ntc_slice ntc_params_get(const ntc_route_params *p, const char *name) {
    ntc_slice key = ntc_slice_cstr(name);
    for (size_t i = 0; i < p->count; i++)
        if (ntc_slice_eq(p->items[i].name, key)) return p->items[i].value;
    return ntc_slice_new(NULL, 0);
}

ntc_err ntc_router_create(ntc_router **out) {
    if (!out) return NTC_ERR_INVALID;
    ntc_router *r = calloc(1, sizeof *r);
    if (!r) return NTC_ERR_OOM;
    *out = r;
    return NTC_OK;
}

void ntc_router_destroy(ntc_router *r) {
    if (!r) return;
    for (size_t i = 0; i < r->count; i++) {
        free(r->routes[i].method);
        free(r->routes[i].pattern);
    }
    free(r->routes);
    free(r);
}

/* Split a path/pattern into segments (slices into `s`). Returns count or -1. */
static int split_segments(const char *s, size_t len, seg_t *out, size_t max) {
    size_t n = 0, i = 0;
    while (i < len) {
        while (i < len && s[i] == '/') i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && s[i] != '/') i++;
        if (n >= max) return -1;
        ntc_slice seg = ntc_slice_new(s + start, i - start);
        bool is_param = seg.len > 1 && seg.ptr[0] == ':';
        if (is_param) { seg.ptr++; seg.len--; }
        out[n].s = seg;
        out[n].is_param = is_param;
        n++;
    }
    return (int)n;
}

ntc_err ntc_router_add(ntc_router *r, const char *method, const char *pattern,
                       ntc_handler h, void *udata) {
    if (!r || !method || !pattern || !h) return NTC_ERR_INVALID;

    if (r->count >= r->cap) {
        size_t ncap = r->cap ? r->cap * 2 : 8;
        route_t *nr = realloc(r->routes, ncap * sizeof *nr);
        if (!nr) return NTC_ERR_OOM;
        r->routes = nr;
        r->cap = ncap;
    }

    route_t *rt = &r->routes[r->count];
    memset(rt, 0, sizeof *rt);
    rt->method = dup_str(method);
    rt->pattern = dup_str(pattern);
    if (!rt->method || !rt->pattern) {
        free(rt->method);
        free(rt->pattern);
        return NTC_ERR_OOM;
    }
    int ns = split_segments(rt->pattern, strlen(rt->pattern), rt->segs, NTC_MAX_SEGMENTS);
    if (ns < 0) {
        free(rt->method);
        free(rt->pattern);
        return NTC_ERR_INVALID;
    }
    rt->nsegs = (size_t)ns;
    rt->handler = h;
    rt->udata = udata;
    r->count++;
    return NTC_OK;
}

ntc_route_status ntc_router_match(const ntc_router *r, ntc_slice method,
                                  ntc_slice path, ntc_handler *out_h,
                                  void **out_udata, ntc_route_params *params) {
    seg_t ps[NTC_MAX_SEGMENTS];
    int pn = split_segments(path.ptr, path.len, ps, NTC_MAX_SEGMENTS);
    bool method_mismatch = false;

    for (size_t i = 0; i < r->count; i++) {
        const route_t *rt = &r->routes[i];
        if (pn < 0 || (size_t)pn != rt->nsegs) continue;

        bool ok = true;
        for (size_t j = 0; j < rt->nsegs; j++) {
            if (rt->segs[j].is_param) continue; /* param matches any segment */
            if (!ntc_slice_eq(rt->segs[j].s, ps[j].s)) { ok = false; break; }
        }
        if (!ok) continue;

        if (!ntc_slice_eq_cstr(method, rt->method)) { method_mismatch = true; continue; }

        if (params) {
            params->count = 0;
            for (size_t j = 0; j < rt->nsegs; j++) {
                if (rt->segs[j].is_param && params->count < NTC_MAX_PARAMS) {
                    params->items[params->count].name = rt->segs[j].s;
                    params->items[params->count].value = ps[j].s;
                    params->count++;
                }
            }
        }
        if (out_h) *out_h = rt->handler;
        if (out_udata) *out_udata = rt->udata;
        return NTC_ROUTE_FOUND;
    }
    return method_mismatch ? NTC_ROUTE_METHOD_NOT_ALLOWED : NTC_ROUTE_NOT_FOUND;
}

size_t ntc_router_count(const ntc_router *r) { return r ? r->count : 0; }

#ifdef UNIT_TEST
#include "ntc/test.h"

static int dummy(const ntc_request *req, const ntc_route_params *p,
                 ntc_response *res, ntc_arena *a, void *u) {
    (void)req; (void)p; (void)res; (void)a; (void)u;
    return 0;
}

TEST(router, exact_match) {
    ntc_router *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_router_create(&r));
    ASSERT_EQ_INT(NTC_OK, ntc_router_add(r, "GET", "/health", dummy, NULL));
    ntc_handler h = NULL; void *u = NULL; ntc_route_params pp;
    ASSERT_EQ_INT(NTC_ROUTE_FOUND,
        ntc_router_match(r, NTC_SLICE_LIT("GET"), NTC_SLICE_LIT("/health"), &h, &u, &pp));
    ASSERT_TRUE(h == dummy);
    ntc_router_destroy(r);
}

TEST(router, param_capture) {
    ntc_router *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_router_create(&r));
    ASSERT_EQ_INT(NTC_OK, ntc_router_add(r, "GET", "/api/users/:id", dummy, NULL));
    ntc_handler h; void *u; ntc_route_params pp;
    ASSERT_EQ_INT(NTC_ROUTE_FOUND,
        ntc_router_match(r, NTC_SLICE_LIT("GET"), NTC_SLICE_LIT("/api/users/42"), &h, &u, &pp));
    ASSERT_EQ_UINT(1u, pp.count);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_params_get(&pp, "id"), "42"));
    ntc_router_destroy(r);
}

TEST(router, two_params) {
    ntc_router *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_router_create(&r));
    ASSERT_EQ_INT(NTC_OK, ntc_router_add(r, "GET", "/o/:oid/items/:iid", dummy, NULL));
    ntc_handler h; void *u; ntc_route_params pp;
    ASSERT_EQ_INT(NTC_ROUTE_FOUND,
        ntc_router_match(r, NTC_SLICE_LIT("GET"), NTC_SLICE_LIT("/o/7/items/x9"), &h, &u, &pp));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_params_get(&pp, "oid"), "7"));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_params_get(&pp, "iid"), "x9"));
    ntc_router_destroy(r);
}

TEST(router, not_found) {
    ntc_router *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_router_create(&r));
    ASSERT_EQ_INT(NTC_OK, ntc_router_add(r, "GET", "/a", dummy, NULL));
    ntc_handler h; void *u; ntc_route_params pp;
    ASSERT_EQ_INT(NTC_ROUTE_NOT_FOUND,
        ntc_router_match(r, NTC_SLICE_LIT("GET"), NTC_SLICE_LIT("/b"), &h, &u, &pp));
    ntc_router_destroy(r);
}

TEST(router, method_not_allowed) {
    ntc_router *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_router_create(&r));
    ASSERT_EQ_INT(NTC_OK, ntc_router_add(r, "GET", "/a", dummy, NULL));
    ntc_handler h; void *u; ntc_route_params pp;
    ASSERT_EQ_INT(NTC_ROUTE_METHOD_NOT_ALLOWED,
        ntc_router_match(r, NTC_SLICE_LIT("POST"), NTC_SLICE_LIT("/a"), &h, &u, &pp));
    ntc_router_destroy(r);
}

TEST(router, length_mismatch_no_match) {
    ntc_router *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_router_create(&r));
    ASSERT_EQ_INT(NTC_OK, ntc_router_add(r, "GET", "/a/:x", dummy, NULL));
    ntc_handler h; void *u; ntc_route_params pp;
    ASSERT_EQ_INT(NTC_ROUTE_NOT_FOUND,
        ntc_router_match(r, NTC_SLICE_LIT("GET"), NTC_SLICE_LIT("/a/b/c"), &h, &u, &pp));
    ntc_router_destroy(r);
}

TEST(router, trailing_slash_ignored) {
    ntc_router *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_router_create(&r));
    ASSERT_EQ_INT(NTC_OK, ntc_router_add(r, "GET", "/health", dummy, NULL));
    ntc_handler h; void *u; ntc_route_params pp;
    ASSERT_EQ_INT(NTC_ROUTE_FOUND,
        ntc_router_match(r, NTC_SLICE_LIT("GET"), NTC_SLICE_LIT("/health/"), &h, &u, &pp));
    ntc_router_destroy(r);
}
#endif /* UNIT_TEST */
