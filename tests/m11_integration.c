/* M11 integration test: WebSockets end to end.
 *
 * A minimal in-test WS client does the Upgrade handshake against the gateway
 * (routing to the ws_echo controller), checks the RFC Sec-WebSocket-Accept,
 * sends a masked text frame, and reads back the controller's greeting plus the
 * echo. Runs in the ASan/UBSan binary, so the WS relay's malloc/free paths
 * (upgrade, inbound, outbound) are instrumented. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* a masked client frame (len <= 125) */
static size_t ws_client_frame(uint8_t op, const char *data, size_t len, uint8_t *out) {
    out[0] = (uint8_t)(0x80 | op);
    out[1] = (uint8_t)(0x80 | len);
    uint8_t key[4] = { 0x12, 0x34, 0x56, 0x78 };
    memcpy(out + 2, key, 4);
    for (size_t i = 0; i < len; i++) out[6 + i] = (uint8_t)data[i] ^ key[i & 3];
    return 6 + len;
}

/* decode one unmasked server frame; 0=need more, -1=bad, else consumed bytes */
static int srv_frame(const uint8_t *p, size_t n, uint8_t *op, const uint8_t **pay, size_t *plen) {
    if (n < 2) return 0;
    *op = p[0] & 0x0f;
    if (p[1] & 0x80) return -1; /* server frames must not be masked */
    size_t len = p[1] & 0x7f, off = 2;
    if (len == 126) { if (n < 4) return 0; len = ((size_t)p[2] << 8) | p[3]; off = 4; }
    else if (len == 127) return -1;
    if (n < off + len) return 0;
    *pay = p + off; *plen = len;
    return (int)(off + len);
}

ITEST(m11, ws_echo) {
    it_iso("m11ws");
    setenv("NTC_CONTROLLER_BIN", "./build/ws_echo", 1);
    setenv("NTC_CONTROLLER_ROUTE", "GET /api/ws", 1);
    const char *argv[] = { "./build/ntc", "start", "38211", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_CONTROLLER_ROUTE");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38211, 4000));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_TRUE(fd >= 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(38211);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    ASSERT_EQ_INT(0, connect(fd, (struct sockaddr *)&a, sizeof a));
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* RFC 6455 example key -> known accept value */
    const char *hs =
        "GET /api/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    ASSERT_TRUE(write(fd, hs, strlen(hs)) == (ssize_t)strlen(hs));

    uint8_t acc[8192]; size_t alen = 0, hdr_end = 0;
    while (alen < sizeof acc) {
        ssize_t r = recv(fd, acc + alen, sizeof acc - alen, 0);
        if (r <= 0) break;
        alen += (size_t)r;
        for (size_t i = 0; i + 3 < alen; i++)
            if (acc[i] == '\r' && acc[i+1] == '\n' && acc[i+2] == '\r' && acc[i+3] == '\n') { hdr_end = i + 4; break; }
        if (hdr_end) break;
    }
    ASSERT_TRUE(hdr_end > 0);
    char hdr[2048];
    size_t hc = hdr_end < sizeof hdr - 1 ? hdr_end : sizeof hdr - 1;
    memcpy(hdr, acc, hc); hdr[hc] = '\0';
    ASSERT_TRUE(strstr(hdr, "101 Switching Protocols") != NULL);
    ASSERT_TRUE(strstr(hdr, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != NULL);

    /* send a masked "hello" */
    uint8_t hf[64];
    size_t hn = ws_client_frame(0x1, "hello", 5, hf);
    ASSERT_TRUE(write(fd, hf, hn) == (ssize_t)hn);

    /* collect the greeting + echo */
    size_t off = hdr_end;
    bool got_welcome = false, got_echo = false;
    for (int iter = 0; iter < 40 && !(got_welcome && got_echo); iter++) {
        for (;;) {
            uint8_t op; const uint8_t *pay; size_t pl;
            int c = srv_frame(acc + off, alen - off, &op, &pay, &pl);
            if (c <= 0) break;
            if (op == 0x1) {
                if (pl == 7 && memcmp(pay, "welcome", 7) == 0) got_welcome = true;
                if (pl == 11 && memcmp(pay, "echo: hello", 11) == 0) got_echo = true;
            }
            off += (size_t)c;
        }
        if (got_welcome && got_echo) break;
        if (alen == sizeof acc) break;
        ssize_t r = recv(fd, acc + alen, sizeof acc - alen, 0);
        if (r <= 0) break;
        alen += (size_t)r;
    }
    ASSERT_TRUE(got_welcome);
    ASSERT_TRUE(got_echo);

    /* polite close frame, then hang up */
    uint8_t cf[8];
    size_t cn = ws_client_frame(0x8, "", 0, cf);
    (void)!write(fd, cf, cn);
    close(fd);
    it_stop(srv);
}
