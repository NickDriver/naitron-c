/* router.h - method+path routing and the controller contract.
 *
 * A controller is an ntc_handler: it receives the parsed request and path
 * params, and fills an ntc_response (allocating body bytes in the provided
 * arena). In P3 handlers are in-process function pointers; P4 keeps the same
 * request-in/response-out contract across the IPC boundary. */
#ifndef NTC_ROUTER_H
#define NTC_ROUTER_H

#include <stddef.h>

#include "ntc/arena.h"
#include "ntc/err.h"
#include "ntc/http.h"
#include "ntc/slice.h"

#define NTC_MAX_PARAMS 8

/* ntc_response lives in http.h (shared with controllers). */

typedef struct ntc_route_params {
    struct { ntc_slice name, value; } items[NTC_MAX_PARAMS];
    size_t count;
} ntc_route_params;

/* Look up a captured path param by name; empty slice if absent. */
ntc_slice ntc_params_get(const ntc_route_params *p, const char *name);

/* Returns 0 on success (res filled), non-zero to signal a 500. */
typedef int (*ntc_handler)(const ntc_request *req,
                           const ntc_route_params *params,
                           ntc_response *res, ntc_arena *a, void *udata);

typedef struct ntc_router ntc_router;

NTC_NODISCARD ntc_err ntc_router_create(ntc_router **out);
void ntc_router_destroy(ntc_router *r);

/* Register `pattern` (e.g. "/api/users/:id"); `:name` segments capture. */
NTC_NODISCARD ntc_err ntc_router_add(ntc_router *r, const char *method,
                                     const char *pattern, ntc_handler h,
                                     void *udata);

typedef enum ntc_route_status {
    NTC_ROUTE_FOUND,
    NTC_ROUTE_NOT_FOUND,
    NTC_ROUTE_METHOD_NOT_ALLOWED
} ntc_route_status;

ntc_route_status ntc_router_match(const ntc_router *r, ntc_slice method,
                                  ntc_slice path, ntc_handler *out_h,
                                  void **out_udata, ntc_route_params *params);

size_t ntc_router_count(const ntc_router *r);

#endif /* NTC_ROUTER_H */
