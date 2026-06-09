/* middleware.h - the gateway middleware chain (general-purpose cross-cutting).
 *
 * Built-ins: request-id, access-log, CORS, rate-limit. The before-chain runs
 * synchronously and may short-circuit (CORS preflight, 429); the after-hook logs
 * once the final status is known. Custom middleware can be layered later. */
#ifndef NTC_MIDDLEWARE_H
#define NTC_MIDDLEWARE_H

#include <stdbool.h>
#include "ntc/http.h"
#include "ntc/slice.h"

typedef struct ntc_mw_config {
    bool request_id;        /* add an X-Request-Id header             */
    bool access_log;        /* log method/path/status/duration        */
    char cors_origin[128];  /* "" off, "*" any, or an explicit origin */
    int rate_per_sec;       /* 0 = off                                */
    int rate_burst;
    char auth_mode[16];     /* "none" | "apikey" | "jwt" (HS256)      */
    char auth_secret[256];  /* API key, or the HS256 secret           */
    char auth_protect[128]; /* path prefix to protect ("" = all)      */
} ntc_mw_config;

typedef struct ntc_mw ntc_mw;

ntc_mw *ntc_mw_new(const ntc_mw_config *cfg);
void ntc_mw_free(ntc_mw *m);

typedef struct ntc_mw_result {
    bool short_circuit;
    int status;
    ntc_slice content_type;
    ntc_slice body;
    char extra_headers[512]; /* added to whatever response is sent  */
    char request_id[40];
} ntc_mw_result;

/* Run the before-chain. Returns true if a response should be sent immediately. */
bool ntc_mw_before(ntc_mw *m, const ntc_request *req, const char *client_ip,
                   long now_ms, ntc_mw_result *r);

/* Emit the access log once the final status + duration are known. */
void ntc_mw_after(ntc_mw *m, const char *method, const char *path,
                  const char *request_id, int status, long duration_ms);

/* token-bucket primitive, exposed for testing */
typedef struct ntc_bucket { double tokens; long last_ms; } ntc_bucket;
bool ntc_bucket_allow(ntc_bucket *b, long now_ms, double rate_per_sec, double burst);

#endif /* NTC_MIDDLEWARE_H */
