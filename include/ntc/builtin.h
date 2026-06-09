/* builtin.h - the core's built-in in-process controllers (P3). */
#ifndef NTC_BUILTIN_H
#define NTC_BUILTIN_H

#include "ntc/router.h"

/* Register GET /health, GET /version, GET /api/echo/:name. */
NTC_NODISCARD ntc_err ntc_builtin_register(ntc_router *r);

#endif /* NTC_BUILTIN_H */
