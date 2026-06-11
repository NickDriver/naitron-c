/* Integration test: controllers can set response headers (redirect, custom).
 * hello_controller redirects when given ?redirect=<url>, also setting X-Test. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ITEST(headers, controller_redirect_and_custom) {
    it_iso("hdrredir");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    const char *argv[] = { "./build/ntc", "start", "38260", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38260, 4000));

    /* a controller-issued redirect: 302 + Location + a custom header */
    char resp[4096];
    ASSERT_TRUE(it_get(38260, "/api/hello?redirect=/dashboard", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(302, it_status(resp));
    ASSERT_TRUE(strstr(resp, "Location: /dashboard") != NULL);
    ASSERT_TRUE(strstr(resp, "X-Test: hello") != NULL);

    /* a normal (no-header) response is unaffected */
    char r2[4096];
    ASSERT_TRUE(it_get(38260, "/api/hello", r2, sizeof r2) > 0);
    ASSERT_EQ_INT(200, it_status(r2));
    ASSERT_TRUE(strstr(r2, "\"controller\":\"hello\"") != NULL);
    ASSERT_TRUE(strstr(r2, "Location:") == NULL);

    it_stop(srv);
}
