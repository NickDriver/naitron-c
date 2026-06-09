/* M5 integration tests: controllers written in Python, TypeScript, Go, Rust
 * all speak the v2 wire protocol through the C gateway. */
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

/* Spawn the core with `bin` as the controller, hit /api/hello/<name>, and check
 * the JSON body contains the expected controller tag + the path param. */
static void run_lang(ntc_test_ctx *t, const char *tag, const char *bin, int port,
                     const char *expect_controller) {
    it_iso(tag);
    setenv("NTC_CONTROLLER_BIN", bin, 1);
    char ports[8]; snprintf(ports, sizeof ports, "%d", port);
    const char *argv[] = { "./build/ntc", "start", ports, "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(port, 5000));

    char resp[8192];
    char path[64]; snprintf(path, sizeof path, "/api/hello/%s", tag);
    /* a slow interpreter may still be starting; retry on 503 for a few seconds */
    int code = 0;
    for (int i = 0; i < 40; i++) {
        if (it_get(port, path, resp, sizeof resp) > 0) { code = it_status(resp); if (code == 200) break; }
        struct timespec ts = { 0, 200 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ_INT(200, code);
    ASSERT_TRUE(strstr(resp, expect_controller) != NULL);
    char want[80]; snprintf(want, sizeof want, "\"name\":\"%s\"", tag);
    ASSERT_TRUE(strstr(resp, want) != NULL);

    it_stop(srv);
}

ITEST(m5, python_controller) {
    if (!have_cmd("python3")) SKIP("python3 not installed");
    run_lang(t, "py", "./sdk/python/example.py", 38130, "\"controller\":\"py-hello\"");
}

ITEST(m5, typescript_controller) {
    if (!have_cmd("node")) SKIP("node not installed");
    run_lang(t, "ts", "./sdk/typescript/example.ts", 38131, "\"controller\":\"ts-hello\"");
}

ITEST(m5, go_controller) {
    if (access("./build/go_controller", X_OK) != 0)
        SKIP("build it: cd sdk/go && go build -o ../../build/go_controller ./example");
    run_lang(t, "go", "./build/go_controller", 38132, "\"controller\":\"go-hello\"");
}

ITEST(m5, rust_controller) {
    if (access("./sdk/rust/target/debug/examples/hello", X_OK) != 0)
        SKIP("build it: cd sdk/rust && cargo build --example hello");
    run_lang(t, "rs", "./sdk/rust/target/debug/examples/hello", 38133, "\"controller\":\"rust-hello\"");
}
