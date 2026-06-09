/* M2 integration tests: request-id, CORS, rate-limit middleware over HTTP. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdlib.h>
#include <string.h>

ITEST(m2, request_id_header) {
    it_iso("m2rid");
    const char *argv[] = { "./build/ntc", "start", "38100", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38100, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38100, "/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "X-Request-Id:") != NULL);

    it_stop(srv);
}

ITEST(m2, cors_preflight_and_headers) {
    it_iso("m2cors");
    setenv("NTC_CORS_ORIGIN", "*", 1);
    const char *argv[] = { "./build/ntc", "start", "38101", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CORS_ORIGIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38101, 4000));

    char resp[8192];
    /* preflight OPTIONS short-circuits 204 with CORS headers */
    ASSERT_TRUE(it_send(38101, "OPTIONS /api/x HTTP/1.1\r\nHost: localhost\r\n\r\n", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(204, it_status(resp));
    ASSERT_TRUE(strstr(resp, "Access-Control-Allow-Origin: *") != NULL);

    /* normal request also carries the CORS header */
    ASSERT_TRUE(it_get(38101, "/health", resp, sizeof resp) > 0);
    ASSERT_TRUE(strstr(resp, "Access-Control-Allow-Origin: *") != NULL);

    it_stop(srv);
}

ITEST(m2, rate_limit_429) {
    it_iso("m2rl");
    setenv("NTC_RATELIMIT_PER_SEC", "2", 1);
    setenv("NTC_RATELIMIT_BURST", "2", 1);
    const char *argv[] = { "./build/ntc", "start", "38102", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_RATELIMIT_PER_SEC");
    unsetenv("NTC_RATELIMIT_BURST");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38102, 4000));

    char resp[8192];
    int got429 = 0;
    for (int i = 0; i < 6; i++) {
        if (it_get(38102, "/health", resp, sizeof resp) > 0 && it_status(resp) == 429) got429++;
    }
    ASSERT_TRUE(got429 >= 1); /* burst 2 -> rapid extras get limited */

    it_stop(srv);
}
