/* M8 integration tests: SSE / streaming responses (wire v3).
 *
 * The sse_controller (controllers/sse_controller.c) streams N events; the
 * gateway relays them as text/event-stream (or chunked). We seed it as the
 * default controller via NTC_CONTROLLER_BIN so GET /api/hello drives it. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"
#include "it_tls.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* position of `needle` in `hay`, or -1 */
static int idx_of(const char *hay, const char *needle) {
    const char *p = strstr(hay, needle);
    return p ? (int)(p - hay) : -1;
}

/* true if events tick 0..n-1 are all present and in increasing order */
static bool ticks_ordered(const char *resp, int n) {
    int prev = -1;
    for (int i = 0; i < n; i++) {
        char tok[32];
        snprintf(tok, sizeof tok, "tick %d", i);
        int at = idx_of(resp, tok);
        if (at < 0 || at <= prev) return false;
        prev = at;
    }
    return true;
}

static pid_t spawn_sse(int port, int tls_port, const char *bin) {
    setenv("NTC_CONTROLLER_BIN", bin, 1);
    if (tls_port) {
        setenv("NTC_TLS_CERT", "tests/vectors/tls.cert.pem", 1);
        setenv("NTC_TLS_KEY", "tests/vectors/tls.key.pem", 1);
    }
    char ps[8], ts[8];
    snprintf(ps, sizeof ps, "%d", port);
    pid_t srv;
    if (tls_port) {
        snprintf(ts, sizeof ts, "%d", tls_port);
        const char *argv[] = { "./build/ntc", "start", ps, "--no-dashboard", "--tls", ts, NULL };
        srv = it_spawn(argv);
    } else {
        const char *argv[] = { "./build/ntc", "start", ps, "--no-dashboard", NULL };
        srv = it_spawn(argv);
    }
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_TLS_CERT"); unsetenv("NTC_TLS_KEY");
    return srv;
}

ITEST(m8, sse_plaintext) {
    it_iso("m8sse");
    pid_t srv = spawn_sse(38170, 0, "./build/sse_controller");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38170, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38170, "/api/hello?n=5", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "Content-Type: text/event-stream") != NULL);
    ASSERT_TRUE(strstr(resp, "Content-Length") == NULL); /* streamed: no length */
    ASSERT_TRUE(strstr(resp, "event: message") != NULL);
    ASSERT_TRUE(ticks_ordered(resp, 5));

    it_stop(srv);
}

ITEST(m8, sse_tls) {
    it_iso("m8ssetls");
    pid_t srv = spawn_sse(38171, 38172, "./build/sse_controller");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38172, 4000));

    char resp[8192];
    ASSERT_TRUE(it_tls_get(38172, "/api/hello?n=4", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "text/event-stream") != NULL);
    ASSERT_TRUE(ticks_ordered(resp, 4));

    it_stop(srv);
}

ITEST(m8, chunked_mode) {
    it_iso("m8chunk");
    pid_t srv = spawn_sse(38173, 0, "./build/sse_controller");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38173, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38173, "/api/hello?n=3&mode=chunked", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "Transfer-Encoding: chunked") != NULL);
    ASSERT_TRUE(strstr(resp, "chunk 0") != NULL);
    ASSERT_TRUE(strstr(resp, "chunk 2") != NULL);
    ASSERT_TRUE(strstr(resp, "0\r\n\r\n") != NULL); /* chunked terminator */

    it_stop(srv);
}

ITEST(m8, many_events) {
    it_iso("m8many");
    pid_t srv = spawn_sse(38174, 0, "./build/sse_controller");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38174, 4000));

    char *resp = malloc(256 * 1024);
    ASSERT_NOT_NULL(resp);
    ASSERT_TRUE(it_get(38174, "/api/hello?n=200", resp, 256 * 1024) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(ticks_ordered(resp, 200)); /* all 200 events present and ordered */
    free(resp);

    it_stop(srv);
}

/* The atomic (v2) path must be untouched: an unmodified one-shot controller,
 * routed through the new range-accepting parser + split gw_deliver, still 200s. */
ITEST(m8, v2_atomic_still_works) {
    it_iso("m8v2");
    pid_t srv = spawn_sse(38175, 0, "./build/hello_controller");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38175, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38175, "/api/hello", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "Content-Length") != NULL); /* atomic: has a length */
    ASSERT_TRUE(strstr(resp, "\"controller\":\"hello\"") != NULL);

    it_stop(srv);
}

/* Connect, send a streaming request, read a little, then hang up mid-stream.
 * The server must not crash or leak the inflight slot. */
static void early_disconnect(int port, const char *path) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) {
        char req[256];
        int n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path);
        if (n > 0) { (void)!write(fd, req, (size_t)n); char b[64]; (void)!read(fd, b, sizeof b); }
    }
    close(fd); /* hang up, possibly mid-stream */
}

ITEST(m8, client_disconnect_midstream) {
    it_iso("m8disc");
    pid_t srv = spawn_sse(38176, 0, "./build/sse_controller");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38176, 4000));

    /* many early disconnects on a slow stream (delay spaces events out so the
     * close lands mid-stream) - the slot must be reclaimed each time */
    for (int i = 0; i < 40; i++) early_disconnect(38176, "/api/hello?n=50&delay=1");

    /* server still healthy and serving full streams */
    char resp[8192];
    ASSERT_TRUE(it_get(38176, "/api/hello?n=3", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(ticks_ordered(resp, 3));

    it_stop(srv);
}
