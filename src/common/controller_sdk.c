#define _GNU_SOURCE /* POSIX read/write/getenv under -std=c23 on Linux */
#include "ntc/controller.h"
#include "ntc/wire.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NTC_CTL_MAX_PAYLOAD (256 * 1024)

static int read_full(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0) return 0; /* EOF */
        if (errno == EINTR) continue;
        return -1;
    }
    return 1;
}

static int write_full(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return 1;
}

static int send_frame(int fd, uint8_t type, uint32_t rid,
                      const uint8_t *payload, uint32_t plen) {
    uint8_t hdr[NTC_WIRE_HEADER_LEN];
    ntc_wire_write_header(hdr, type, rid, plen);
    if (write_full(fd, hdr, sizeof hdr) <= 0) return -1;
    if (plen && write_full(fd, payload, plen) <= 0) return -1;
    return 0;
}

int ntc_controller_run(const ntc_controller *ctl) {
    if (!ctl || !ctl->handle) return 2;

    const char *fds = getenv("NTC_CONTROLLER_FD");
    if (!fds) { fprintf(stderr, "controller: NTC_CONTROLLER_FD not set\n"); return 2; }
    int fd = atoi(fds);
    if (fd < 0) return 2;

    const char *name = ctl->name ? ctl->name : "controller";
    if (send_frame(fd, NTC_MSG_HELLO, 0, (const uint8_t *)name,
                   (uint32_t)strlen(name)) != 0)
        return 1;

    static uint8_t payload[NTC_CTL_MAX_PAYLOAD];
    for (;;) {
        uint8_t hdr[NTC_WIRE_HEADER_LEN];
        int r = read_full(fd, hdr, sizeof hdr);
        if (r <= 0) break; /* core closed the connection */

        ntc_wire_header h;
        if (!ntc_wire_parse_header(hdr, &h)) {
            fprintf(stderr, "controller: bad frame header\n");
            break;
        }
        if (h.length > sizeof payload) { fprintf(stderr, "controller: payload too big\n"); break; }
        if (h.length && read_full(fd, payload, h.length) <= 0) break;

        if (h.type == NTC_MSG_WELCOME) continue;
        if (h.type == NTC_MSG_PING) { (void)send_frame(fd, NTC_MSG_PONG, h.request_id, NULL, 0); continue; }
        if (h.type != NTC_MSG_REQUEST) continue;

        ntc_arena a;
        if (ntc_arena_init(&a, 16 * 1024) != NTC_OK) break;

        ntc_response res = { .status = 200,
                             .content_type = NTC_SLICE_LIT("application/json"),
                             .body = NTC_SLICE_LIT("") };
        ntc_request req;
        if (!ntc_wire_decode_request(payload, h.length, &req)) {
            res.status = 400;
            res.content_type = NTC_SLICE_LIT("text/plain");
            res.body = NTC_SLICE_LIT("bad request");
        } else if (ctl->handle(&req, &res, &a, ctl->udata) != 0) {
            res.status = 500;
            res.content_type = NTC_SLICE_LIT("application/json");
            res.body = NTC_SLICE_LIT("{\"error\":\"controller error\"}");
        }

        size_t cap = res.body.len + res.content_type.len + 64;
        uint8_t *out = ntc_arena_alloc(&a, cap);
        if (out) {
            ssize_t pl = ntc_wire_encode_response(res.status, res.content_type,
                                                  res.body, out, cap);
            if (pl > 0)
                (void)send_frame(fd, NTC_MSG_RESPONSE, h.request_id, out, (uint32_t)pl);
        }
        ntc_arena_destroy(&a);
    }
    return 0;
}
