#define _GNU_SOURCE /* MSG_NOSIGNAL on Linux; harmless on macOS */
#include "ntc/server.h"

#include "ntc/arena.h"
#include "ntc/builtin.h"
#include "ntc/http.h"
#include "ntc/log.h"
#include "ntc/poller.h"
#include "ntc/registry.h"
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
#include <time.h>
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
#define NTC_BACKOFF_BASE   200    /* ms */
#define NTC_BACKOFF_MAX    5000   /* ms */
#define NTC_STABLE_MS      5000   /* uptime after which backoff resets */

#define JSON NTC_SLICE_LIT("application/json")

enum { KIND_HTTP = 1, KIND_CTRL = 2 };
enum { CS_READ, CS_WAIT, CS_WRITE };

static volatile sig_atomic_t g_stop = 0;
static void on_stop(int sig) { (void)sig; g_stop = 1; }

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

struct gateway;
struct service;

typedef struct conn {
    int kind;            /* KIND_HTTP (must be first) */
    int fd;
    int state;
    struct gateway *gw;
    bool inflight;
    uint32_t req_id;
    struct ctrl *wait_ctrl;
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
    struct service *svc;
    struct gateway *gw;
    uint8_t *rbuf; size_t rlen, rcap;
    uint8_t *wbuf; size_t wlen, wsent, wcap;
} ctrl;

typedef struct service {
    char *name;
    char *bin;
    ctrl *conn;          /* current process connection; NULL when down */
    int restart_count;
    long restart_at;     /* monotonic ms; when to (re)spawn */
    long spawned_at;     /* monotonic ms; current process start */
    int backoff_ms;
    struct gateway *gw;
} service;

typedef struct gateway {
    ntc_poller *p;
    ntc_router *router;
    ntc_registry *reg;
    int listen_fd;
    service *services;
    size_t nservices;
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
static int  spawn_service(gateway *g, service *svc);

/* ---- utilities ---- */
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
    *buf = n; *cap = ncap;
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
    c->wbuf = resp.ptr; c->wlen = resp.len; c->wsent = 0; c->state = CS_WRITE;
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
    conn_close(g, c);
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
    if (!c || (g->gen[slot] & 0xFFFFFu) != gen) return;
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
    service *svc = ct->svc;
    NTC_ERROR("controller '%s' (pid %ld) died", svc ? svc->name : "?", (long)ct->pid);

    (void)ntc_poller_del(g->p, ct->fd);
    close(ct->fd);
    waitpid(ct->pid, NULL, WNOHANG);

    for (uint32_t i = 0; i < NTC_MAX_INFLIGHT; i++) {
        conn *c = g->pending[i];
        if (!c || c->wait_ctrl != ct) continue;
        gw_free_slot(g, (uint16_t)i);
        c->inflight = false;
        (void)respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"controller died\"}"));
    }

    if (svc) {
        svc->conn = NULL;
        svc->restart_count++;
        int b = svc->backoff_ms ? svc->backoff_ms * 2 : NTC_BACKOFF_BASE;
        if (b > NTC_BACKOFF_MAX) b = NTC_BACKOFF_MAX;
        svc->backoff_ms = b;
        svc->restart_at = now_ms() + b;
    }
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

/* ---- routing / forwarding ---- */
static int forward_marker(const ntc_request *r, const ntc_route_params *p,
                          ntc_response *res, ntc_arena *a, void *u) {
    (void)r; (void)p; (void)res; (void)a; (void)u; return 0;
}

static int gw_forward(gateway *g, conn *c, const ntc_request *req, service *svc) {
    if (!svc->conn)
        return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"service unavailable\"}"));

    uint8_t *enc = ntc_arena_alloc(&c->arena, NTC_CONN_RBUF + 1024);
    if (!enc) return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"oom\"}"));
    ssize_t pl = ntc_wire_encode_request(req, enc, NTC_CONN_RBUF + 1024);
    if (pl < 0) return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"encode failed\"}"));

    uint32_t id;
    if (gw_alloc_id(g, c, &id) != 0)
        return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"too many in-flight\"}"));
    if (ctrl_queue(svc->conn, NTC_MSG_REQUEST, id, enc, (uint32_t)pl) != 0) {
        gw_free_slot(g, (uint16_t)(id & NTC_INFLIGHT_MASK));
        return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"queue full\"}"));
    }
    c->state = CS_WAIT;
    c->req_id = id;
    c->inflight = true;
    c->wait_ctrl = svc->conn;
    (void)ctrl_update_poll(g, svc->conn);
    return 0;
}

static int gw_dispatch(gateway *g, conn *c, const ntc_request *req) {
    ntc_handler h = NULL;
    void *udata = NULL;
    ntc_route_params params;
    ntc_route_status rs = ntc_router_match(g->router, req->method, req->path, &h, &udata, &params);

    if (rs == NTC_ROUTE_NOT_FOUND)
        return respond_and_flush(g, c, 404, NTC_SLICE_LIT("{\"error\":\"not found\"}"));
    if (rs == NTC_ROUTE_METHOD_NOT_ALLOWED)
        return respond_and_flush(g, c, 405, NTC_SLICE_LIT("{\"error\":\"method not allowed\"}"));
    if (h == forward_marker) return gw_forward(g, c, req, (service *)udata);

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

static void on_wait_readable(gateway *g, conn *c) {
    char tmp[256];
    ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
    if (n == 0) { conn_close(g, c); return; }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        conn_close(g, c);
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
            ntc_arena_destroy(&c->arena); close(cfd); free(c);
        }
    }
}

/* ---- spawn + supervise ---- */
static int spawn_service(gateway *g, service *svc) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(sv[0]); close(sv[1]); return -1; }
    if (pid == 0) {
        close(sv[0]);
        char fdbuf[16];
        snprintf(fdbuf, sizeof fdbuf, "%d", sv[1]);
        setenv("NTC_CONTROLLER_FD", fdbuf, 1);
        execlp(svc->bin, svc->bin, (char *)NULL);
        _exit(127);
    }
    close(sv[1]);
    int fd = sv[0];

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
        close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0);
        return -1;
    }
    if (h.length > 0) {
        uint8_t tmp[256];
        uint32_t take = h.length > sizeof tmp ? (uint32_t)sizeof tmp : h.length;
        (void)read_full(fd, tmp, take);
    }
    uint8_t welcome[NTC_WIRE_HEADER_LEN];
    ntc_wire_write_header(welcome, NTC_MSG_WELCOME, 0, 0);
    if (write(fd, welcome, sizeof welcome) != (ssize_t)sizeof welcome) {
        close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return -1;
    }
    tv.tv_sec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (set_nonblocking(fd) < 0) { close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return -1; }

    ctrl *ct = calloc(1, sizeof *ct);
    if (!ct) { close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return -1; }
    ct->kind = KIND_CTRL;
    ct->fd = fd;
    ct->pid = pid;
    ct->svc = svc;
    ct->gw = g;
    if (ntc_poller_add(g->p, fd, NTC_POLL_READ, ct) != NTC_OK) {
        free(ct); close(fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return -1;
    }
    svc->conn = ct;
    svc->spawned_at = now_ms();
    return 0;
}

static void supervise(gateway *g) {
    long t = now_ms();
    for (size_t i = 0; i < g->nservices; i++) {
        service *svc = &g->services[i];
        if (!svc->conn) {
            if (t >= svc->restart_at) {
                if (spawn_service(g, svc) == 0) {
                    NTC_SUCCESS("controller '%s' %s (pid %ld)", svc->name,
                                svc->restart_count ? "restarted" : "ready",
                                (long)svc->conn->pid);
                } else {
                    int b = svc->backoff_ms ? svc->backoff_ms * 2 : NTC_BACKOFF_BASE;
                    if (b > NTC_BACKOFF_MAX) b = NTC_BACKOFF_MAX;
                    svc->backoff_ms = b;
                    svc->restart_at = t + b;
                    NTC_WARN("controller '%s' spawn failed; retry in %dms", svc->name, b);
                }
            }
        } else if (svc->backoff_ms > NTC_BACKOFF_BASE && t - svc->spawned_at > NTC_STABLE_MS) {
            svc->backoff_ms = NTC_BACKOFF_BASE; /* stable: reset backoff */
        }
    }
}

static int poll_timeout(gateway *g) {
    int to = 1000;
    long t = now_ms();
    for (size_t i = 0; i < g->nservices; i++) {
        if (!g->services[i].conn) {
            long d = g->services[i].restart_at - t;
            if (d < 0) d = 0;
            if (d < to) to = (int)d;
        }
    }
    return to;
}

/* ---- registry load ---- */
static service *find_service(gateway *g, const char *name) {
    for (size_t i = 0; i < g->nservices; i++)
        if (strcmp(g->services[i].name, name) == 0) return &g->services[i];
    return NULL;
}

static ntc_err load_registry(gateway *g) {
    /* Seed a default controller from $NTC_CONTROLLER_BIN if the registry is empty. */
    ntc_service_row srows[64];
    size_t scount = 0;
    NTC_TRY(ntc_registry_list_services(g->reg, srows, 64, &scount));
    if (scount == 0) {
        const char *bin = getenv("NTC_CONTROLLER_BIN");
        if (bin) {
            if (ntc_registry_add_service(g->reg, "hello", bin) == NTC_OK) {
                (void)ntc_registry_add_route(g->reg, "GET", "/api/hello", "hello");
                (void)ntc_registry_add_route(g->reg, "GET", "/api/hello/:name", "hello");
                NTC_TRY(ntc_registry_list_services(g->reg, srows, 64, &scount));
            }
        }
    }
    if (scount == 0) return NTC_OK; /* built-ins only */

    g->services = calloc(scount, sizeof(service));
    if (!g->services) return NTC_ERR_OOM;
    g->nservices = scount;
    for (size_t i = 0; i < scount; i++) {
        g->services[i].name = strdup(srows[i].name);
        g->services[i].bin = strdup(srows[i].bin);
        g->services[i].gw = g;
        g->services[i].backoff_ms = NTC_BACKOFF_BASE;
    }

    ntc_route_row rrows[256];
    size_t rcount = 0;
    NTC_TRY(ntc_registry_list_routes(g->reg, rrows, 256, &rcount));
    for (size_t i = 0; i < rcount; i++) {
        service *svc = find_service(g, rrows[i].service);
        if (!svc) continue;
        if (ntc_router_add(g->router, rrows[i].method, rrows[i].pattern,
                           forward_marker, svc) != NTC_OK)
            NTC_WARN("failed to register route %s %s", rrows[i].method, rrows[i].pattern);
    }
    return NTC_OK;
}

ntc_err ntc_server_run(uint16_t port, uint16_t admin_port) {
    (void)admin_port; /* read-only dashboard: P8 */

    gateway g;
    memset(&g, 0, sizeof g);
    gw_slots_init(&g);

    if (ntc_router_create(&g.router) != NTC_OK) return NTC_ERR_OOM;
    if (ntc_builtin_register(g.router) != NTC_OK) { ntc_router_destroy(g.router); return NTC_ERR_INTERNAL; }

    const char *dbpath = getenv("NTC_DB");
    if (!dbpath) dbpath = "ntc.db";
    if (ntc_registry_open(&g.reg, dbpath) != NTC_OK) {
        NTC_ERROR("cannot open registry '%s'", dbpath);
        ntc_router_destroy(g.router);
        return NTC_ERR_IO;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { NTC_ERROR("socket(): %s", strerror(errno)); goto fail_pre_poll; }
    g.listen_fd = listen_fd;

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(listen_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    if (set_nonblocking(listen_fd) < 0) { close(listen_fd); goto fail_pre_poll; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        NTC_ERROR("bind(:%u): %s", (unsigned)port, strerror(errno)); close(listen_fd); goto fail_pre_poll;
    }
    if (listen(listen_fd, 256) < 0) {
        NTC_ERROR("listen(): %s", strerror(errno)); close(listen_fd); goto fail_pre_poll;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_stop;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (ntc_poller_create(&g.p) != NTC_OK) { close(listen_fd); goto fail_pre_poll; }
    if (ntc_poller_add(g.p, listen_fd, NTC_POLL_READ, NULL) != NTC_OK) {
        ntc_poller_destroy(g.p); close(listen_fd); goto fail_pre_poll;
    }

    if (load_registry(&g) != NTC_OK) NTC_WARN("registry load incomplete");
    for (size_t i = 0; i < g.nservices; i++) (void)spawn_service(&g, &g.services[i]);

    NTC_SUCCESS("naitron-c listening on http://0.0.0.0:%u  (%s, %zu routes, %zu services)",
                (unsigned)port, ntc_poller_backend(), ntc_router_count(g.router), g.nservices);

    ntc_poll_event evs[NTC_MAX_EVENTS];
    while (!g_stop) {
        int n = ntc_poller_wait(g.p, evs, NTC_MAX_EVENTS, poll_timeout(&g));
        if (n < 0) {
            if (errno == EINTR) { supervise(&g); continue; }
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
            } else {
                if (evs[i].events & NTC_POLL_WRITE) (void)on_writable(&g, c);
            }
        }
        supervise(&g);
    }

    NTC_INFO("shutting down");
    for (size_t i = 0; i < g.nservices; i++) {
        service *svc = &g.services[i];
        if (svc->conn) {
            kill(svc->conn->pid, SIGTERM);
            close(svc->conn->fd);
            waitpid(svc->conn->pid, NULL, 0);
            free(svc->conn->rbuf); free(svc->conn->wbuf); free(svc->conn);
        }
        free(svc->name); free(svc->bin);
    }
    free(g.services);
    ntc_poller_destroy(g.p);
    close(listen_fd);
    ntc_registry_close(g.reg);
    ntc_router_destroy(g.router);
    return NTC_OK;

fail_pre_poll:
    ntc_registry_close(g.reg);
    ntc_router_destroy(g.router);
    return NTC_ERR_IO;
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
