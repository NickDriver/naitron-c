#define _GNU_SOURCE /* MSG_NOSIGNAL on Linux; harmless on macOS */
#include "ntc/server.h"

#include "ntc/arena.h"
#include "ntc/builtin.h"
#include "ntc/http.h"
#include "ntc/log.h"
#include "ntc/poller.h"
#include "ntc/router.h"
#include "ntc/slice.h"
#include "ntc/wire.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define NTC_MAX_EVENTS     256
#define NTC_CONN_RBUF      (16 * 1024)
#define NTC_INFLIGHT_BITS  12
#define NTC_MAX_INFLIGHT   (1u << NTC_INFLIGHT_BITS)
#define NTC_INFLIGHT_MASK  (NTC_MAX_INFLIGHT - 1u)
#define NTC_CTRL_MAX_RBUF  (4u * 1024 * 1024)

#define JSON NTC_SLICE_LIT("application/json")

enum { KIND_HTTP = 1, KIND_CTRL = 2 };
enum { CS_READ, CS_WAIT, CS_WRITE };

static volatile sig_atomic_t g_stop = 0;
static void on_stop(int sig) { (void)sig; g_stop = 1; }

struct gateway;

typedef struct conn {
    int kind;            /* KIND_HTTP (must be first) */
    int fd;
    int state;
    struct gateway *gw;
    bool inflight;
    uint32_t req_id;
    ntc_arena arena;
    size_t rlen;
    const char *wbuf;
    size_t wlen, wsent;
    char rbuf[NTC_CONN_RBUF];
} conn;

typedef struct ctrl {
    int kind;            /* KIND_CTRL (must be first) */
    int fd;
    pid_t pid;
    char *name;
    struct gateway *gw;
    uint8_t *rbuf; size_t rlen, rcap;
    uint8_t *wbuf; size_t wlen, wsent, wcap;
} ctrl;

typedef struct gateway {
    ntc_poller *p;
    ntc_router *router;
    int listen_fd;
    ctrl *controller;                  /* P4: a single controller */
    conn *pending[NTC_MAX_INFLIGHT];
    uint32_t gen[NTC_MAX_INFLIGHT];
    uint16_t free_slots[NTC_MAX_INFLIGHT];
    size_t free_top;
} gateway;

/* ---- forward declarations ---- */
static void conn_close(gateway *g, conn *c);
static int  on_writable(gateway *g, conn *c);
static int  respond_and_flush(gateway *g, conn *c, int status, ntc_slice json);
static void controller_died(gateway *g, ctrl *ct);

/* ---- small utilities ---- */
static int set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int read_full(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0) return 0;
        if (errno == EINTR) continue;
        return -1;
    }
    return 1;
}

static int buf_reserve(uint8_t **buf, size_t *cap, size_t need) {
    if (need <= *cap) return 0;
    size_t ncap = *cap ? *cap : 4096;
    while (ncap < need) ncap *= 2;
    uint8_t *n = realloc(*buf, ncap);
    if (!n) return -1;
    *buf = n;
    *cap = ncap;
    return 0;
}

/* ---- inflight slot table (ABA-safe via per-slot generation) ---- */
static void gw_slots_init(gateway *g) {
    for (uint32_t i = 0; i < NTC_MAX_INFLIGHT; i++) g->free_slots[i] = (uint16_t)i;
    g->free_top = NTC_MAX_INFLIGHT;
}
static int gw_alloc_id(gateway *g, conn *c, uint32_t *out_id) {
    if (g->free_top == 0) return -1;
    uint16_t slot = g->free_slots[--g->free_top];
    g->pending[slot] = c;
    *out_id = ((g->gen[slot] & 0xFFFFFu) << NTC_INFLIGHT_BITS) | slot;
    return 0;
}
static void gw_free_slot(gateway *g, uint16_t slot) {
    g->pending[slot] = NULL;
    g->gen[slot]++;
    g->free_slots[g->free_top++] = slot;
}

/* ---- connections ---- */
static conn *conn_new(gateway *g, int fd) {
    conn *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->kind = KIND_HTTP;
    c->fd = fd;
    c->state = CS_READ;
    c->gw = g;
    if (ntc_arena_init(&c->arena, 4096) != NTC_OK) { free(c); return NULL; }
    return c;
}

static void conn_close(gateway *g, conn *c) {
    if (c->inflight) { gw_free_slot(g, (uint16_t)(c->req_id & NTC_INFLIGHT_MASK)); c->inflight = false; }
    (void)ntc_poller_del(g->p, c->fd);
    close(c->fd);
    ntc_arena_destroy(&c->arena);
    free(c);
}

static int conn_respond(conn *c, int status, ntc_slice ctype, ntc_slice body) {
    ntc_slice resp;
    if (ntc_http_format_response(&c->arena, status, ntc_http_status_text(status),
                                 ctype, body, &resp) != NTC_OK)
        return -1;
    c->wbuf = resp.ptr;
    c->wlen = resp.len;
    c->wsent = 0;
    c->state = CS_WRITE;
    return 0;
}

static int conn_flush(gateway *g, conn *c) {
    if (ntc_poller_mod(g->p, c->fd, NTC_POLL_WRITE, c) != NTC_OK) { conn_close(g, c); return -1; }
    return on_writable(g, c);
}

static int respond_and_flush(gateway *g, conn *c, int status, ntc_slice json) {
    if (conn_respond(c, status, JSON, json) != 0) { conn_close(g, c); return -1; }
    return conn_flush(g, c);
}

static int on_writable(gateway *g, conn *c) {
    while (c->wsent < c->wlen) {
        ssize_t n = send(c->fd, c->wbuf + c->wsent, c->wlen - c->wsent, MSG_NOSIGNAL);
        if (n > 0) { c->wsent += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        conn_close(g, c);
        return -1;
    }
    conn_close(g, c); /* Connection: close */
    return -1;
}

/* ---- controller plumbing ---- */
static int ctrl_queue(ctrl *ct, uint8_t type, uint32_t rid,
                      const uint8_t *payload, uint32_t plen) {
    size_t need = ct->wlen + NTC_WIRE_HEADER_LEN + plen;
    if (buf_reserve(&ct->wbuf, &ct->wcap, need) != 0) return -1;
    ntc_wire_write_header(ct->wbuf + ct->wlen, type, rid, plen);
    if (plen) memcpy(ct->wbuf + ct->wlen + NTC_WIRE_HEADER_LEN, payload, plen);
    ct->wlen += NTC_WIRE_HEADER_LEN + plen;
    return 0;
}

static int ctrl_update_poll(gateway *g, ctrl *ct) {
    uint32_t ev = NTC_POLL_READ;
    if (ct->wsent < ct->wlen) ev |= NTC_POLL_WRITE;
    return ntc_poller_mod(g->p, ct->fd, ev, ct) == NTC_OK ? 0 : -1;
}

static void gw_deliver(gateway *g, uint32_t id, const uint8_t *payload, size_t len) {
    uint16_t slot = (uint16_t)(id & NTC_INFLIGHT_MASK);
    uint32_t gen = id >> NTC_INFLIGHT_BITS;
    conn *c = g->pending[slot];
    if (!c || (g->gen[slot] & 0xFFFFFu) != gen) return; /* stale / client gone */
    gw_free_slot(g, slot);
    c->inflight = false;

    int status; ntc_slice ctype, body;
    if (!ntc_wire_decode_response(payload, len, &status, &ctype, &body)) {
        (void)respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"bad upstream response\"}"));
        return;
    }
    if (conn_respond(c, status, ctype, body) != 0) { conn_close(g, c); return; }
    (void)conn_flush(g, c);
}

static void controller_died(gateway *g, ctrl *ct) {
    NTC_ERROR("controller '%s' (pid %ld) died", ct->name ? ct->name : "?", (long)ct->pid);
    (void)ntc_poller_del(g->p, ct->fd);
    close(ct->fd);
    waitpid(ct->pid, NULL, WNOHANG);
    if (g->controller == ct) g->controller = NULL;
    for (uint32_t i = 0; i < NTC_MAX_INFLIGHT; i++) {
        conn *c = g->pending[i];
        if (!c) continue;
        gw_free_slot(g, (uint16_t)i);
        c->inflight = false;
        (void)respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"controller died\"}"));
    }
    free(ct->name);
    free(ct->rbuf);
    free(ct->wbuf);
    free(ct);
}

static void on_ctrl_writable(gateway *g, ctrl *ct) {
    while (ct->wsent < ct->wlen) {
        ssize_t n = send(ct->fd, ct->wbuf + ct->wsent, ct->wlen - ct->wsent, MSG_NOSIGNAL);
        if (n > 0) { ct->wsent += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        controller_died(g, ct);
        return;
    }
    if (ct->wsent >= ct->wlen) { ct->wsent = 0; ct->wlen = 0; }
    (void)ctrl_update_poll(g, ct);
}

/* returns 0 if controller still alive, -1 if it died (and was freed) */
static int on_ctrl_readable(gateway *g, ctrl *ct) {
    for (;;) {
        if (buf_reserve(&ct->rbuf, &ct->rcap, ct->rlen + 16384) != 0) { controller_died(g, ct); return -1; }
        ssize_t n = recv(ct->fd, ct->rbuf + ct->rlen, ct->rcap - ct->rlen, 0);
        if (n > 0) {
            ct->rlen += (size_t)n;
            if (ct->rlen > NTC_CTRL_MAX_RBUF) { controller_died(g, ct); return -1; }
            continue;
        }
        if (n == 0) { controller_died(g, ct); return -1; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        controller_died(g, ct);
        return -1;
    }

    size_t off = 0;
    for (;;) {
        ntc_wire_header h; const uint8_t *pl; size_t consumed;
        int r = ntc_wire_read_frame(ct->rbuf + off, ct->rlen - off, &h, &pl, &consumed);
        if (r == 0) break;
        if (r < 0) { controller_died(g, ct); return -1; }
        if (h.type == NTC_MSG_RESPONSE) gw_deliver(g, h.request_id, pl, h.length);
        off += consumed;
    }
    if (off > 0) { memmove(ct->rbuf, ct->rbuf + off, ct->rlen - off); ct->rlen -= off; }
    return 0;
}

/* ---- request routing ---- */

/* Sentinel handler value meaning "forward this route to a controller process".
 * The address is compared, never called. */
static int forward_marker(const ntc_request *r, const ntc_route_params *p,
                          ntc_response *res, ntc_arena *a, void *u) {
    (void)r; (void)p; (void)res; (void)a; (void)u; return 0;
}

static int gw_forward(gateway *g, conn *c, const ntc_request *req) {
    ctrl *ct = g->controller;
    if (!ct) return respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"controller unavailable\"}"));

    uint8_t *enc = ntc_arena_alloc(&c->arena, NTC_CONN_RBUF + 1024);
    if (!enc) return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"oom\"}"));
    ssize_t pl = ntc_wire_encode_request(req, enc, NTC_CONN_RBUF + 1024);
    if (pl < 0) return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"encode failed\"}"));

    uint32_t id;
    if (gw_alloc_id(g, c, &id) != 0)
        return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"too many in-flight\"}"));
    if (ctrl_queue(ct, NTC_MSG_REQUEST, id, enc, (uint32_t)pl) != 0) {
        gw_free_slot(g, (uint16_t)(id & NTC_INFLIGHT_MASK));
        return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"queue full\"}"));
    }
    c->state = CS_WAIT;
    c->req_id = id;
    c->inflight = true;
    (void)ctrl_update_poll(g, ct);
    return 0; /* parked, awaiting controller */
}

static int gw_dispatch(gateway *g, conn *c, const ntc_request *req) {
    ntc_handler h = NULL;
    void *udata = NULL;
    ntc_route_params params;
    ntc_route_status rs = ntc_router_match(g->router, req->method, req->path,
                                           &h, &udata, &params);

    if (rs == NTC_ROUTE_NOT_FOUND)
        return respond_and_flush(g, c, 404, NTC_SLICE_LIT("{\"error\":\"not found\"}"));
    if (rs == NTC_ROUTE_METHOD_NOT_ALLOWED)
        return respond_and_flush(g, c, 405, NTC_SLICE_LIT("{\"error\":\"method not allowed\"}"));

    if (h == forward_marker) return gw_forward(g, c, req);

    ntc_response res = { .status = 200, .content_type = JSON, .body = NTC_SLICE_LIT("") };
    if (h(req, &params, &res, &c->arena, udata) != 0)
        return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"internal error\"}"));
    if (conn_respond(c, res.status, res.content_type, res.body) != 0) { conn_close(g, c); return -1; }
    return conn_flush(g, c);
}

static int on_readable(gateway *g, conn *c) {
    bool eof = false;
    for (;;) {
        if (c->rlen >= sizeof c->rbuf) break;
        ssize_t n = recv(c->fd, c->rbuf + c->rlen, sizeof c->rbuf - c->rlen, 0);
        if (n > 0) { c->rlen += (size_t)n; continue; }
        if (n == 0) { eof = true; break; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        conn_close(g, c);
        return -1;
    }

    ntc_request req;
    size_t consumed = 0;
    ntc_parse_result pr = ntc_http_parse_request(c->rbuf, c->rlen, &req, &consumed);

    if (pr == NTC_PARSE_INCOMPLETE) {
        if (eof) { conn_close(g, c); return -1; }
        if (c->rlen < sizeof c->rbuf) return 0;
        return respond_and_flush(g, c, 431, NTC_SLICE_LIT("{\"error\":\"headers too large\"}"));
    }
    if (pr == NTC_PARSE_ERROR)
        return respond_and_flush(g, c, 400, NTC_SLICE_LIT("{\"error\":\"bad request\"}"));

    size_t need = consumed;
    if (req.has_content_length &&
        ntc_size_add(consumed, req.content_length, &need) != NTC_OK)
        return respond_and_flush(g, c, 400, NTC_SLICE_LIT("{\"error\":\"bad length\"}"));
    if (req.has_content_length && need > c->rlen) {
        if (eof) { conn_close(g, c); return -1; }
        if (c->rlen < sizeof c->rbuf) return 0;
        return respond_and_flush(g, c, 413, NTC_SLICE_LIT("{\"error\":\"body too large\"}"));
    }

    return gw_dispatch(g, c, &req);
}

/* A parked connection only needs to be watched for the client hanging up. */
static void on_wait_readable(gateway *g, conn *c) {
    char tmp[256];
    ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
    if (n == 0) { conn_close(g, c); return; }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        conn_close(g, c);
    /* extra bytes before the response are ignored (Connection: close) */
}

static void accept_all(gateway *g) {
    for (;;) {
        int cfd = accept(g->listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            NTC_WARN("accept(): %s", strerror(errno));
            return;
        }
        if (set_nonblocking(cfd) < 0) { close(cfd); continue; }
#ifdef SO_NOSIGPIPE
        int one = 1;
        setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        conn *c = conn_new(g, cfd);
        if (!c) { close(cfd); continue; }
        if (ntc_poller_add(g->p, cfd, NTC_POLL_READ, c) != NTC_OK) {
            ntc_arena_destroy(&c->arena);
            close(cfd);
            free(c);
        }
    }
}

/* ---- controller spawn + handshake ---- */
static ctrl *spawn_controller(gateway *g, const char *bin, const char *name) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) { close(sv[0]); close(sv[1]); return NULL; }
    if (pid == 0) {
        close(sv[0]);
        char fdbuf[16];
        snprintf(fdbuf, sizeof fdbuf, "%d", sv[1]);
        setenv("NTC_CONTROLLER_FD", fdbuf, 1);
        execlp(bin, bin, (char *)NULL);
        _exit(127);
    }
    close(sv[1]);
    int fd = sv[0];

    /* blocking handshake with a short timeout */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif

    uint8_t hdr[NTC_WIRE_HEADER_LEN];
    ntc_wire_header h;
    if (read_full(fd, hdr, sizeof hdr) <= 0 || !ntc_wire_parse_header(hdr, &h) ||
        h.type != NTC_MSG_HELLO) {
        NTC_ERROR("controller '%s': handshake failed", name);
        close(fd);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return NULL;
    }
    if (h.length > 0) {
        uint8_t tmp[256];
        uint32_t take = h.length > sizeof tmp ? (uint32_t)sizeof tmp : h.length;
        (void)read_full(fd, tmp, take);
    }
    uint8_t welcome[NTC_WIRE_HEADER_LEN];
    ntc_wire_write_header(welcome, NTC_MSG_WELCOME, 0, 0);
    if (write(fd, welcome, sizeof welcome) != (ssize_t)sizeof welcome) {
        close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return NULL;
    }

    tv.tv_sec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (set_nonblocking(fd) < 0) { close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return NULL; }

    ctrl *ct = calloc(1, sizeof *ct);
    if (!ct) { close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return NULL; }
    ct->kind = KIND_CTRL;
    ct->fd = fd;
    ct->pid = pid;
    ct->name = strdup(name);
    ct->gw = g;
    if (ntc_poller_add(g->p, fd, NTC_POLL_READ, ct) != NTC_OK) {
        free(ct->name); free(ct); close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0);
        return NULL;
    }
    NTC_SUCCESS("controller '%s' ready (pid %ld)", name, (long)pid);
    return ct;
}

ntc_err ntc_server_run(uint16_t port, uint16_t admin_port) {
    (void)admin_port; /* read-only dashboard: P8 */

    gateway g;
    memset(&g, 0, sizeof g);
    gw_slots_init(&g);

    if (ntc_router_create(&g.router) != NTC_OK) return NTC_ERR_OOM;
    if (ntc_builtin_register(g.router) != NTC_OK) { ntc_router_destroy(g.router); return NTC_ERR_INTERNAL; }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { NTC_ERROR("socket(): %s", strerror(errno)); ntc_router_destroy(g.router); return NTC_ERR_IO; }
    g.listen_fd = listen_fd;

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(listen_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    if (set_nonblocking(listen_fd) < 0) { close(listen_fd); ntc_router_destroy(g.router); return NTC_ERR_IO; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        NTC_ERROR("bind(:%u): %s", (unsigned)port, strerror(errno));
        close(listen_fd); ntc_router_destroy(g.router); return NTC_ERR_IO;
    }
    if (listen(listen_fd, 256) < 0) {
        NTC_ERROR("listen(): %s", strerror(errno));
        close(listen_fd); ntc_router_destroy(g.router); return NTC_ERR_IO;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_stop;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (ntc_poller_create(&g.p) != NTC_OK) {
        close(listen_fd); ntc_router_destroy(g.router); return NTC_ERR_IO;
    }
    if (ntc_poller_add(g.p, listen_fd, NTC_POLL_READ, NULL) != NTC_OK) {
        ntc_poller_destroy(g.p); close(listen_fd); ntc_router_destroy(g.router); return NTC_ERR_IO;
    }

    /* P4: optionally spawn one controller and forward a route to it. */
    const char *bin = getenv("NTC_CONTROLLER_BIN");
    if (bin) {
        g.controller = spawn_controller(&g, bin, "hello");
        if (g.controller) {
            if (ntc_router_add(g.router, "GET", "/api/hello", forward_marker, NULL) != NTC_OK ||
                ntc_router_add(g.router, "GET", "/api/hello/:name", forward_marker, NULL) != NTC_OK)
                NTC_WARN("failed to register controller routes");
        } else {
            NTC_WARN("controller '%s' did not start; serving built-ins only", bin);
        }
    }

    NTC_SUCCESS("naitron-c listening on http://0.0.0.0:%u  (%s, %zu routes, Ctrl-C to stop)",
                (unsigned)port, ntc_poller_backend(), ntc_router_count(g.router));

    ntc_poll_event evs[NTC_MAX_EVENTS];
    while (!g_stop) {
        int n = ntc_poller_wait(g.p, evs, NTC_MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            NTC_ERROR("poller_wait(): %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].fd == listen_fd) { accept_all(&g); continue; }
            int kind = *(int *)evs[i].udata;
            if (kind == KIND_CTRL) {
                ctrl *ct = evs[i].udata;
                if ((evs[i].events & NTC_POLL_READ) && on_ctrl_readable(&g, ct) < 0) continue;
                if (evs[i].events & NTC_POLL_WRITE) on_ctrl_writable(&g, ct);
                continue;
            }
            conn *c = evs[i].udata;
            if (c->state == CS_READ) {
                if ((evs[i].events & NTC_POLL_READ) && on_readable(&g, c) < 0) continue;
            } else if (c->state == CS_WAIT) {
                if (evs[i].events & NTC_POLL_READ) on_wait_readable(&g, c);
            } else { /* CS_WRITE */
                if (evs[i].events & NTC_POLL_WRITE) (void)on_writable(&g, c);
            }
        }
    }

    NTC_INFO("shutting down");
    if (g.controller) {
        kill(g.controller->pid, SIGTERM);
        close(g.controller->fd);
        waitpid(g.controller->pid, NULL, 0);
        free(g.controller->name);
        free(g.controller->rbuf);
        free(g.controller->wbuf);
        free(g.controller);
    }
    ntc_poller_destroy(g.p);
    close(listen_fd);
    ntc_router_destroy(g.router);
    return NTC_OK;
}

#ifdef UNIT_TEST
#include "ntc/test.h"
#include <sys/socket.h>

TEST(poller, detects_readable_with_udata) {
    ntc_poller *p = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_poller_create(&p));
    ASSERT_NOT_NULL(p);
    int sv[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    int marker = 42;
    ASSERT_EQ_INT(NTC_OK, ntc_poller_add(p, sv[0], NTC_POLL_READ, &marker));
    ntc_poll_event evs[4];
    ASSERT_EQ_INT(0, ntc_poller_wait(p, evs, 4, 50));
    ASSERT_EQ_INT(1, (int)write(sv[1], "x", 1));
    int n = ntc_poller_wait(p, evs, 4, 1000);
    ASSERT_EQ_INT(1, n);
    ASSERT_EQ_INT(sv[0], evs[0].fd);
    ASSERT_TRUE((evs[0].events & NTC_POLL_READ) != 0);
    ASSERT_TRUE(evs[0].udata == &marker);
    ASSERT_EQ_INT(NTC_OK, ntc_poller_del(p, sv[0]));
    close(sv[0]); close(sv[1]);
    ntc_poller_destroy(p);
}

TEST(poller, write_interest_fires_on_empty_socket) {
    ntc_poller *p = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_poller_create(&p));
    int sv[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    ASSERT_EQ_INT(NTC_OK, ntc_poller_add(p, sv[0], NTC_POLL_WRITE, NULL));
    ntc_poll_event evs[4];
    int n = ntc_poller_wait(p, evs, 4, 1000);
    ASSERT_TRUE(n >= 1);
    ASSERT_TRUE((evs[0].events & NTC_POLL_WRITE) != 0);
    ASSERT_EQ_INT(NTC_OK, ntc_poller_del(p, sv[0]));
    close(sv[0]); close(sv[1]);
    ntc_poller_destroy(p);
}

TEST(poller, mod_switches_interest) {
    ntc_poller *p = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_poller_create(&p));
    int sv[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    ASSERT_EQ_INT(NTC_OK, ntc_poller_add(p, sv[0], NTC_POLL_READ, NULL));
    ntc_poll_event evs[4];
    ASSERT_EQ_INT(0, ntc_poller_wait(p, evs, 4, 50));
    ASSERT_EQ_INT(NTC_OK, ntc_poller_mod(p, sv[0], NTC_POLL_WRITE, NULL));
    int n = ntc_poller_wait(p, evs, 4, 1000);
    ASSERT_TRUE(n >= 1);
    ASSERT_TRUE((evs[0].events & NTC_POLL_WRITE) != 0);
    ASSERT_EQ_INT(NTC_OK, ntc_poller_del(p, sv[0]));
    close(sv[0]); close(sv[1]);
    ntc_poller_destroy(p);
}

TEST(poller, backend_name_known) {
    const char *b = ntc_poller_backend();
    ASSERT_NOT_NULL(b);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(b), "kqueue") ||
                ntc_slice_eq_cstr(ntc_slice_cstr(b), "epoll"));
}
#endif /* UNIT_TEST */
