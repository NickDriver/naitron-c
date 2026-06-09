/* M3 integration tests: API-key and HS256-JWT auth middleware over HTTP. */
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

ITEST(m3, apikey_auth) {
    it_iso("m3key");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_AUTH_MODE", "apikey", 1);
    setenv("NTC_AUTH_SECRET", "secret123", 1);
    setenv("NTC_AUTH_PROTECT", "/api/", 1);
    const char *argv[] = { "./build/ntc", "start", "38110", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_SECRET"); unsetenv("NTC_AUTH_PROTECT");
    unsetenv("NTC_CONTROLLER_BIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38110, 4000));

    char resp[8192];
    /* protected, no key -> 401 */
    ASSERT_TRUE(it_get(38110, "/api/hello", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    /* protected, valid key -> 200 (forwarded) */
    ASSERT_TRUE(it_send(38110,
        "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret123\r\n\r\n",
        resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    /* protected, wrong key -> 401 */
    ASSERT_TRUE(it_send(38110,
        "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer nope\r\n\r\n",
        resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    /* unprotected path -> no auth needed */
    ASSERT_TRUE(it_get(38110, "/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    it_stop(srv);
}

ITEST(m3, jwt_auth) {
    it_iso("m3jwt");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_SECRET", "your-256-bit-secret", 1);
    setenv("NTC_AUTH_PROTECT", "/api/", 1);
    const char *argv[] = { "./build/ntc", "start", "38111", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_SECRET"); unsetenv("NTC_AUTH_PROTECT");
    unsetenv("NTC_CONTROLLER_BIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38111, 4000));

    char req[1024], resp[8192];
    snprintf(req, sizeof req,
        "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", JWT);
    ASSERT_TRUE(it_send(38111, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    /* garbage token -> 401 */
    ASSERT_TRUE(it_send(38111,
        "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer a.b.c\r\n\r\n",
        resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    it_stop(srv);
}
