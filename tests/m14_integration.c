/* M14 integration tests: gzip + worker pools (replicas) + max body + multipart. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int send_raw(int port, const char *req, char *resp, size_t cap) {
    return it_send(port, req, resp, cap);
}

/* ---- gzip: a large, compressible response is gzipped when the client asks ---- */
ITEST(m14, gzip_response) {
    it_iso("m14gz");
    /* a static dir with a big compressible file */
    system("mkdir -p /tmp/ntc_m14_gz && "
           "yes 'the quick brown fox jumps over the lazy dog 0123456789' | head -80 > /tmp/ntc_m14_gz/big.txt");
    setenv("NTC_STATIC_DIR", "/tmp/ntc_m14_gz", 1);
    const char *argv[] = { "./build/ntc", "start", "38240", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_STATIC_DIR");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38240, 4000));

    char resp[16384];
    int n = send_raw(38240,
        "GET /big.txt HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
        resp, sizeof resp);
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "Content-Encoding: gzip") != NULL);
    /* the body after the header terminator begins with the gzip magic 1f 8b */
    char *sep = memmem(resp, (size_t)n, "\r\n\r\n", 4);
    ASSERT_NOT_NULL(sep);
    ASSERT_EQ_INT(0x1f, (unsigned char)sep[4]);
    ASSERT_EQ_INT(0x8b, (unsigned char)sep[5]);

    /* a client that does NOT accept gzip gets plain text */
    char resp2[16384];
    ASSERT_TRUE(it_get(38240, "/big.txt", resp2, sizeof resp2) > 0);
    ASSERT_TRUE(strstr(resp2, "Content-Encoding: gzip") == NULL);
    ASSERT_TRUE(strstr(resp2, "the quick brown fox") != NULL);

    it_stop(srv);
    system("rm -rf /tmp/ntc_m14_gz");
}

/* ---- worker pools: 3 replicas round-robin (distinct controller pids serve) ---- */
ITEST(m14, replicas_round_robin) {
    it_iso("m14rep");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_REPLICAS", "3", 1);
    const char *argv[] = { "./build/ntc", "start", "38241", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_REPLICAS");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38241, 4000));

    /* give the 3 replicas a moment to all come up */
    int seen[8]; int nseen = 0;
    for (int i = 0; i < 24; i++) {
        char resp[4096];
        if (it_get(38241, "/api/hello", resp, sizeof resp) <= 0) continue;
        char *p = strstr(resp, "\"pid\":");
        if (!p) continue;
        int pid = atoi(p + 6);
        bool found = false;
        for (int k = 0; k < nseen; k++) if (seen[k] == pid) found = true;
        if (!found && nseen < 8) seen[nseen++] = pid;
        struct timespec ts = { 0, 60 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    /* more than one distinct replica pid served the requests */
    ASSERT_TRUE(nseen >= 2);

    it_stop(srv);
}

/* ---- configurable max body: a body over the limit is 413'd ---- */
ITEST(m14, max_body_limit) {
    it_iso("m14mb");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_MAX_BODY", "100", 1);
    const char *argv[] = { "./build/ntc", "start", "38242", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_MAX_BODY");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38242, 4000));

    char big[300];
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    char req[700], resp[4096];
    int n = snprintf(req, sizeof req,
        "POST /api/hello HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
        strlen(big), big);
    ASSERT_TRUE(send_raw(38242, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(413, it_status(resp));
    (void)n;

    it_stop(srv);
}

/* ---- multipart: the upload controller parses a form-data body ---- */
ITEST(m14, multipart_upload) {
    it_iso("m14mp");
    setenv("NTC_CONTROLLER_BIN", "./build/upload_echo", 1);
    setenv("NTC_CONTROLLER_ROUTE", "POST /api/upload", 1);
    const char *argv[] = { "./build/ntc", "start", "38243", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_CONTROLLER_ROUTE");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38243, 4000));

    const char *body =
        "--BND\r\n"
        "Content-Disposition: form-data; name=\"field\"\r\n\r\n"
        "hi there\r\n"
        "--BND\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "0123456789\r\n"
        "--BND--\r\n";
    char req[1024], resp[4096];
    int n = snprintf(req, sizeof req,
        "POST /api/upload HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: multipart/form-data; boundary=BND\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(body), body);
    ASSERT_TRUE(n > 0 && (size_t)n < sizeof req);
    ASSERT_TRUE(send_raw(38243, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"parts\":2") != NULL);
    ASSERT_TRUE(strstr(resp, "\"field\":\"hi there\"") != NULL);
    ASSERT_TRUE(strstr(resp, "\"filename\":\"a.txt\"") != NULL);
    ASSERT_TRUE(strstr(resp, "\"filesize\":10") != NULL);

    it_stop(srv);
}
