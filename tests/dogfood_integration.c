/* Dogfood checkpoint test: the examples/ai-chat app end to end.
 *
 * Spawns the gateway with the Python streaming controller mounted at /api/chat
 * and JWT auth on /api, mints an HS256 token with the example's own minter, and
 * asserts: no token -> 401; valid token -> a live SSE token stream carrying the
 * authenticated `sub`. This validates the Python streaming SDK (added at the
 * dogfood checkpoint) + auth-identity passthrough + the example itself.
 * Skips cleanly when python3 is unavailable. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static bool have_cmd(const char *cmd) {
    char buf[256];
    snprintf(buf, sizeof buf, "command -v %s >/dev/null 2>&1", cmd);
    return system(buf) == 0;
}

static bool mint_token(char *out, size_t cap) {
    FILE *p = popen("python3 examples/ai-chat/mint_token.py dev-secret demo-user 2>/dev/null", "r");
    if (!p) return false;
    char *r = fgets(out, (int)cap, p);
    pclose(p);
    if (!r) return false;
    size_t n = strlen(out);
    while (n && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = '\0';
    return n > 20;
}

ITEST(dogfood, chat_streams_with_jwt) {
    if (!have_cmd("python3")) SKIP("python3 not installed");

    it_iso("dogchat");
    setenv("NTC_CONTROLLER_BIN", "examples/ai-chat/chat_controller.py", 1);
    setenv("NTC_CONTROLLER_ROUTE", "GET /api/chat", 1);
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_SECRET", "dev-secret", 1);
    setenv("NTC_AUTH_PROTECT", "/api", 1);
    const char *argv[] = { "./build/ntc", "start", "38202", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_CONTROLLER_ROUTE");
    unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_SECRET"); unsetenv("NTC_AUTH_PROTECT");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38202, 5000));

    char tok[2048];
    if (!mint_token(tok, sizeof tok)) { it_stop(srv); SKIP("could not mint token"); }

    /* no token -> 401 */
    char r0[4096];
    ASSERT_TRUE(it_get(38202, "/api/chat?q=hi", r0, sizeof r0) > 0);
    ASSERT_EQ_INT(401, it_status(r0));

    /* valid token -> SSE stream (retry while the interpreter warms up) */
    char req[4096], resp[8192];
    snprintf(req, sizeof req,
        "GET /api/chat?q=hello+test HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Bearer %s\r\nConnection: close\r\n\r\n", tok);
    int code = 0;
    for (int i = 0; i < 40; i++) {
        if (it_send(38202, req, resp, sizeof resp) > 0) { code = it_status(resp); if (code == 200) break; }
        struct timespec ts = { 0, 200 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ_INT(200, code);
    ASSERT_TRUE(strstr(resp, "text/event-stream") != NULL);
    ASSERT_TRUE(strstr(resp, "event: token") != NULL);
    ASSERT_TRUE(strstr(resp, "[DONE]") != NULL);
    ASSERT_TRUE(strstr(resp, "demo-user") != NULL); /* JWT sub reached the controller */

    it_stop(srv);
}
