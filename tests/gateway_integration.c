/* Integration tests for the gateway: spawn the real ./build/ntc and talk HTTP. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void iso_env(const char *tag) {
    it_iso(tag);
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
}

static int body_pid(const char *resp) {
    const char *b = strstr(resp, "\"pid\":");
    int pid = -1;
    if (b) sscanf(b, "\"pid\":%d", &pid);
    return pid;
}

ITEST(gateway, answers_200_over_tcp) {
    iso_env("p200");
    const char *argv[] = { "./build/ntc", "start", "38081", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38081, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38081, "/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"status\":\"ok\"") != NULL);

    ASSERT_TRUE(it_get(38081, "/nope", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(404, it_status(resp));

    it_stop(srv);
}

ITEST(gateway, forwards_request_to_controller) {
    iso_env("fwd");
    const char *argv[] = { "./build/ntc", "start", "38082", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38082, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38082, "/api/hello", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"controller\":\"hello\"") != NULL);
    ASSERT_TRUE(body_pid(resp) > 0);

    it_stop(srv);
}

ITEST(gateway, restarts_crashed_controller) {
    iso_env("restart");
    const char *argv[] = { "./build/ntc", "start", "38083", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38083, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38083, "/api/hello", resp, sizeof resp) > 0);
    int pid1 = body_pid(resp);
    ASSERT_TRUE(pid1 > 0);

    kill(pid1, SIGKILL); /* crash the controller */

    int pid2 = -1;
    struct timespec slp = { 0, 100 * 1000 * 1000 };
    for (int i = 0; i < 60; i++) { /* up to ~6s for supervisor to restart */
        nanosleep(&slp, NULL);
        if (it_get(38083, "/api/hello", resp, sizeof resp) <= 0) continue;
        int p = body_pid(resp);
        if (p > 0 && p != pid1) { pid2 = p; break; }
    }
    ASSERT_TRUE(pid2 > 0);          /* restarted... */
    ASSERT_TRUE(pid2 != pid1);      /* ...as a new process */

    it_stop(srv);
}
