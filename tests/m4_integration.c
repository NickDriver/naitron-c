/* M4 integration tests: path params + auth identity reach the controller. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *JWT =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

ITEST(m4, path_param_reaches_controller) {
    it_iso("m4p");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    const char *argv[] = { "./build/ntc", "start", "38120", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38120, 4000));

    /* seeded route /api/hello/:name -> controller echoes name */
    char resp[8192];
    ASSERT_TRUE(it_get(38120, "/api/hello/bob", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"name\":\"bob\"") != NULL);

    it_stop(srv);
}

ITEST(m4, auth_identity_reaches_controller) {
    it_iso("m4id");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_SECRET", "your-256-bit-secret", 1);
    setenv("NTC_AUTH_PROTECT", "/api/", 1);
    const char *argv[] = { "./build/ntc", "start", "38121", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_AUTH_MODE");
    unsetenv("NTC_AUTH_SECRET"); unsetenv("NTC_AUTH_PROTECT");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38121, 4000));

    char req[1024], resp[8192];
    snprintf(req, sizeof req,
        "GET /api/hello/x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", JWT);
    ASSERT_TRUE(it_send(38121, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"sub\":\"1234567890\"") != NULL);

    it_stop(srv);
}
