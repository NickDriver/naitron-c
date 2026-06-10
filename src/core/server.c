#define _GNU_SOURCE /* MSG_NOSIGNAL on Linux; harmless on macOS */
#include "ntc/server.h"

#include "ntc/arena.h"
#include "ntc/builtin.h"
#include "ntc/control.h"
#include "ntc/http.h"
#include "ntc/https_client.h"
#include "ntc/json.h"
#include "ntc/jwt.h"
#include "ntc/log.h"
#include "ntc/mcp.h"
#include "ntc/middleware.h"
#include "ntc/poller.h"
#include "ntc/registry.h"
#include "ntc/router.h"
#include "ntc/session.h"
#include "ntc/slice.h"
#include "ntc/tls.h"
#include "ntc/version.h"
#include "ntc/wire.h"
#include "ntc/ws.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
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
#define NTC_MAX_SERVICES   256

#define JSON NTC_SLICE_LIT("application/json")

enum { KIND_HTTP = 1, KIND_CTRL = 2, KIND_CONTROL = 3 };
enum { CS_READ, CS_WAIT, CS_WRITE, CS_STREAM, CS_WS };

/* cap on a single client's buffered-but-unsent streamed bytes; past this the
 * client can't keep up and is disconnected (never throttle the shared
 * controller socket - that would stall its other clients). */
#define NTC_STREAM_MAX_BUF (4u * 1024 * 1024)

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
    bool is_admin;       /* connection arrived on the admin port */
    struct ntc_tls *tls; /* non-NULL for HTTPS connections (TLS termination) */
    struct gateway *gw;
    bool inflight;
    uint32_t req_id;
    struct ctrl *wait_ctrl;
    /* middleware / access-log state */
    char client_ip[46];
    char request_id[40];
    char extra_headers[512];
    char log_method[16];
    char log_path[200];
    char auth_sub[128];
    char auth_scope[256];
    long req_start;
    bool logged;
    ntc_arena arena;
    size_t rlen;
    const char *wbuf;
    size_t wlen, wsent;
    /* streaming (CS_STREAM) state; swbuf is a growable heap drain buffer that
     * chunks append to and the writer frees as they go out. */
    bool streaming;       /* this conn is in a streamed response */
    bool stream_sse;      /* true=SSE raw passthrough, false=chunked framing */
    bool stream_head_sent;/* the response head has been queued */
    bool stream_ended;    /* RESPONSE_END seen; close once swbuf drains */
    bool is_ws;           /* upgraded to a WebSocket (CS_WS); reuses swbuf out */
    uint8_t *swbuf;
    size_t swlen, swsent, swcap;
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
    bool disabled;       /* removed via control plane; do not restart */
    int restart_count;
    long restart_at;     /* monotonic ms; when to (re)spawn */
    long spawned_at;     /* monotonic ms; current process start */
    int backoff_ms;
    long long bin_mtime; /* dev mode: last-seen mtime of `bin` (0 = unseen) */
    struct gateway *gw;
} service;

/* a short-lived control-plane client connection */
typedef struct cctrl {
    int kind;            /* KIND_CONTROL (must be first) */
    int fd;
    struct gateway *gw;
    size_t len;
    char buf[4096];
} cctrl;

typedef struct metrics {
    long start_ms;
    uint64_t requests_total;
    uint64_t status_2xx, status_4xx, status_5xx;
    uint64_t forwarded, builtin;
} metrics;

typedef struct gateway {
    ntc_poller *p;
    ntc_router *router;
    ntc_registry *reg;
    int listen_fd;
    int admin_fd;
    int control_fd;
    int tls_fd;          /* HTTPS listener; -1 = disabled */
    ntc_tls_conf *tls_conf;
    metrics m;
    ntc_mw *mw;
    char token[65];
    char app_name[128];
    char static_dir[256]; /* serve files from here when no route matches ("" = off) */
    service *services;   /* fixed array, cap NTC_MAX_SERVICES (stable pointers) */
    size_t nservices;
    conn *pending[NTC_MAX_INFLIGHT];
    uint32_t gen[NTC_MAX_INFLIGHT];
    uint16_t free_slots[NTC_MAX_INFLIGHT];
    size_t free_top;
    /* dev mode (ntc dev): mtime watch + hot reload */
    bool dev_watch;
    const char *dev_build;                       /* build command, or NULL */
    const char *dev_paths[NTC_DEV_MAX_WATCH];    /* watched source files/dirs */
    long long dev_path_mtime[NTC_DEV_MAX_WATCH]; /* last-seen max mtime (0=unseen) */
    size_t dev_npaths;
    long dev_last_poll_ms;
    /* OAuth2 login + sessions (M12) */
    bool oauth_enabled;
    char oauth_authorize_url[256];
    char oauth_token_url[256];
    char oauth_client_id[160];
    char oauth_client_secret[256];
    char oauth_redirect_uri[256];
    char oauth_scopes[160];
    char oauth_success[128];   /* post-login redirect target (default "/") */
    ntc_ca *oauth_ca;            /* trust anchors for the token endpoint */
    ntc_kvstore *sessions;       /* session-id -> "sub\tscope" */
    ntc_kvstore *oauth_pending;  /* oauth state -> pkce verifier */
} gateway;

/* ---- forward declarations ---- */
static void conn_close(gateway *g, conn *c);
static int  on_writable(gateway *g, conn *c);
static int  respond_and_flush(gateway *g, conn *c, int status, ntc_slice json);
static int  process_request(gateway *g, conn *c, bool eof);
static int  tls_drive_write(gateway *g, conn *c);
static int  tls_set_interest(gateway *g, conn *c);
static void on_tls_event(gateway *g, conn *c);
static void controller_died(gateway *g, ctrl *ct);
static int  spawn_service(gateway *g, service *svc);
static void exec_control_command(gateway *g, char *cmdline, char *out, size_t cap);
static int  ctrl_queue(ctrl *ct, uint8_t type, uint32_t rid, const uint8_t *payload, uint32_t plen);
static int  ctrl_update_poll(gateway *g, ctrl *ct);
static int  on_ws_readable(gateway *g, conn *c);

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

static void rec_status(gateway *g, int status) {
    g->m.requests_total++;
    if (status >= 500) g->m.status_5xx++;
    else if (status >= 400) g->m.status_4xx++;
    else if (status >= 200 && status < 300) g->m.status_2xx++;
}

/* ---- connections ---- */
static conn *conn_new(gateway *g, int fd) {
    conn *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->kind = KIND_HTTP;
    c->fd = fd;
    c->state = CS_READ;
    c->gw = g;
    c->req_start = now_ms();
    if (ntc_arena_init(&c->arena, 4096) != NTC_OK) { free(c); return NULL; }
    return c;
}

static void conn_close(gateway *g, conn *c) {
    /* a WebSocket torn down (client EOF/error) -> tell the controller so its
     * ws_close fires. Done before freeing the slot, while it is still valid. */
    if (c->is_ws && c->inflight && c->wait_ctrl) {
        uint8_t cb[2];
        ssize_t pl = ntc_wire_encode_ws_close(1000, cb, sizeof cb);
        if (pl > 0 && ctrl_queue(c->wait_ctrl, NTC_MSG_WS_CLOSE, c->req_id, cb, (uint32_t)pl) == 0)
            (void)ctrl_update_poll(g, c->wait_ctrl);
    }
    if (c->inflight) { gw_free_slot(g, (uint16_t)(c->req_id & NTC_INFLIGHT_MASK)); c->inflight = false; }
    (void)ntc_poller_del(g->p, c->fd);
    close(c->fd);
    if (c->tls) ntc_tls_free(c->tls);
    free(c->swbuf);
    ntc_arena_destroy(&c->arena);
    free(c);
}

static int conn_respond(conn *c, int status, ntc_slice ctype, ntc_slice body) {
    ntc_slice resp;
    if (ntc_http_format_response_ex(&c->arena, status, ntc_http_status_text(status), ctype,
                                    c->extra_headers[0] ? c->extra_headers : NULL,
                                    body, &resp) != NTC_OK)
        return -1;
    c->wbuf = resp.ptr; c->wlen = resp.len; c->wsent = 0; c->state = CS_WRITE;
    if (!c->is_admin && !c->logged && c->gw->mw) {
        ntc_mw_after(c->gw->mw, c->log_method, c->log_path, c->request_id, status,
                     now_ms() - c->req_start);
        c->logged = true;
    }
    return 0;
}

static int conn_flush(gateway *g, conn *c) {
    if (c->tls) {
        int rc = tls_drive_write(g, c);
        if (rc < 0) return rc;            /* conn closed (done or error) */
        return tls_set_interest(g, c);    /* re-arm WRITE if records still pending */
    }
    if (ntc_poller_mod(g->p, c->fd, NTC_POLL_WRITE, c) != NTC_OK) { conn_close(g, c); return -1; }
    return on_writable(g, c);
}

static int respond_and_flush(gateway *g, conn *c, int status, ntc_slice json) {
    if (!c->is_admin) rec_status(g, status);
    if (conn_respond(c, status, JSON, json) != 0) { conn_close(g, c); return -1; }
    return conn_flush(g, c);
}

/* respond without touching request metrics (reserved endpoints, admin, landing) */
static int send_resp(gateway *g, conn *c, int status, ntc_slice ctype, ntc_slice body) {
    if (conn_respond(c, status, ctype, body) != 0) { conn_close(g, c); return -1; }
    return conn_flush(g, c);
}

static int on_writable(gateway *g, conn *c) {
    if (c->tls) return tls_drive_write(g, c);
    if (c->streaming) {
        while (c->swsent < c->swlen) {
            ssize_t n = send(c->fd, c->swbuf + c->swsent, c->swlen - c->swsent, MSG_NOSIGNAL);
            if (n > 0) { c->swsent += (size_t)n; continue; }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0; /* stay armed */
            conn_close(g, c);
            return -1;
        }
        c->swlen = c->swsent = 0;                  /* fully drained: reset */
        if (c->stream_ended) { conn_close(g, c); return -1; }
        /* nothing to send now - wait for the next chunk (or client EOF) on READ */
        if (ntc_poller_mod(g->p, c->fd, NTC_POLL_READ, c) != NTC_OK) { conn_close(g, c); return -1; }
        return 0;
    }
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

/* Resolve the client conn for an inflight id (ABA-checked). NULL if it's gone. */
static conn *gw_conn_for_id(gateway *g, uint32_t id) {
    uint16_t slot = (uint16_t)(id & NTC_INFLIGHT_MASK);
    uint32_t gen = id >> NTC_INFLIGHT_BITS;
    conn *c = g->pending[slot];
    if (!c || (g->gen[slot] & 0xFFFFFu) != gen) return NULL;
    return c;
}

static void gw_deliver(gateway *g, uint32_t id, const uint8_t *payload, size_t len) {
    conn *c = gw_conn_for_id(g, id);
    if (!c) return;
    gw_free_slot(g, (uint16_t)(id & NTC_INFLIGHT_MASK));
    c->inflight = false;

    int status; ntc_slice ctype, body;
    if (!ntc_wire_decode_response(payload, len, &status, &ctype, &body)) {
        (void)respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"bad upstream response\"}"));
        return;
    }
    rec_status(g, status);
    if (conn_respond(c, status, ctype, body) != 0) { conn_close(g, c); return; }
    (void)conn_flush(g, c);
}

/* ---- streamed responses (relay controller chunks to the client) ---- */

/* Arm WRITE + drain the streaming buffer (plaintext or TLS). <0 if conn closed. */
static int stream_kick(gateway *g, conn *c) {
    if (c->tls) {
        int rc = tls_drive_write(g, c);
        if (rc < 0) return -1;
        return tls_set_interest(g, c);
    }
    if (ntc_poller_mod(g->p, c->fd, NTC_POLL_READ | NTC_POLL_WRITE, c) != NTC_OK) { conn_close(g, c); return -1; }
    return on_writable(g, c);
}

/* Append n bytes to the drain buffer (compacting first), enforce the
 * backpressure cap (disconnect a slow client rather than stall the shared
 * controller), then push. Returns <0 if the conn was closed. */
static int stream_push(gateway *g, conn *c, const void *data, size_t n) {
    if (n) {
        if (c->swsent > 0) { /* compact consumed prefix to bound growth */
            memmove(c->swbuf, c->swbuf + c->swsent, c->swlen - c->swsent);
            c->swlen -= c->swsent; c->swsent = 0;
        }
        if (c->swlen + n > NTC_STREAM_MAX_BUF) { conn_close(g, c); return -1; }
        if (buf_reserve(&c->swbuf, &c->swcap, c->swlen + n) != 0) { conn_close(g, c); return -1; }
        memcpy(c->swbuf + c->swlen, data, n);
        c->swlen += n;
    }
    return stream_kick(g, c);
}

static void gw_deliver_begin(gateway *g, uint32_t id, const uint8_t *payload, size_t len) {
    conn *c = gw_conn_for_id(g, id);
    if (!c) return;
    int status; uint8_t flags; ntc_slice ctype;
    if (!ntc_wire_decode_response_begin(payload, len, &status, &flags, &ctype)) {
        gw_free_slot(g, (uint16_t)(id & NTC_INFLIGHT_MASK)); c->inflight = false;
        (void)respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"bad stream begin\"}"));
        return;
    }
    rec_status(g, status);
    c->streaming = true;
    c->stream_sse = (flags & NTC_STREAM_FLAG_SSE) != 0;
    c->state = CS_STREAM;
    ntc_slice head;
    if (ntc_http_format_stream_head(&c->arena, status, ntc_http_status_text(status), ctype,
                                    c->stream_sse, c->extra_headers[0] ? c->extra_headers : NULL,
                                    &head) != NTC_OK) {
        conn_close(g, c); return;
    }
    if (!c->is_admin && !c->logged && g->mw) { /* access-log now; status is known */
        ntc_mw_after(g->mw, c->log_method, c->log_path, c->request_id, status, now_ms() - c->req_start);
        c->logged = true;
    }
    c->stream_head_sent = true;
    (void)stream_push(g, c, head.ptr, head.len);
}

static void gw_deliver_chunk(gateway *g, uint32_t id, const uint8_t *payload, size_t len) {
    conn *c = gw_conn_for_id(g, id);
    if (!c || !c->streaming) return; /* client gone or no BEGIN -> drop */
    ntc_slice data;
    if (!ntc_wire_decode_chunk(payload, len, &data) || data.len == 0) return;
    if (c->stream_sse) {
        (void)stream_push(g, c, data.ptr, data.len); /* raw passthrough */
    } else {
        char hdr[32];
        int hn = snprintf(hdr, sizeof hdr, "%zx\r\n", data.len); /* chunked size line */
        if (hn < 0) return;
        if (stream_push(g, c, hdr, (size_t)hn) < 0) return;
        if (stream_push(g, c, data.ptr, data.len) < 0) return;
        (void)stream_push(g, c, "\r\n", 2);
    }
}

static void gw_deliver_end(gateway *g, uint32_t id) {
    conn *c = gw_conn_for_id(g, id);
    if (!c) return;
    gw_free_slot(g, (uint16_t)(id & NTC_INFLIGHT_MASK)); /* slot done at END */
    c->inflight = false;
    if (!c->streaming) { conn_close(g, c); return; } /* END without BEGIN */
    c->stream_ended = true;
    if (!c->stream_sse) { (void)stream_push(g, c, "0\r\n\r\n", 5); return; } /* chunked terminator + close */
    (void)stream_push(g, c, NULL, 0); /* SSE: kick a final drain; on_writable closes when empty */
}

/* ---- WebSockets (relay between client frames and controller WS_MSG) ---- */

/* controller -> client: encode a WS message and push it to the socket. */
static void gw_ws_deliver(gateway *g, uint32_t id, const uint8_t *payload, size_t len) {
    conn *c = gw_conn_for_id(g, id);
    if (!c || !c->is_ws) return;
    uint8_t opcode; ntc_slice data;
    if (!ntc_wire_decode_ws_msg(payload, len, &opcode, &data)) return;
    /* WS_MSG opcode convention 1=text/2=binary == ntc_ws_opcode NTC_WS_TEXT/BIN */
    ntc_ws_opcode wsop = (opcode == (uint8_t)NTC_WS_BIN) ? NTC_WS_BIN : NTC_WS_TEXT;
    size_t cap = data.len + 16;
    uint8_t *frame = malloc(cap);
    if (!frame) return;
    ssize_t fn = ntc_ws_encode(wsop, (const uint8_t *)data.ptr, data.len, frame, cap);
    if (fn > 0) (void)stream_push(g, c, frame, (size_t)fn);
    free(frame);
}

/* controller -> client: close the WebSocket (send a close frame, then close). */
static void gw_ws_deliver_close(gateway *g, uint32_t id) {
    conn *c = gw_conn_for_id(g, id);
    if (!c) return;
    gw_free_slot(g, (uint16_t)(id & NTC_INFLIGHT_MASK)); /* controller initiated; no notify-back */
    c->inflight = false;
    uint8_t cf[4];
    ssize_t cn = ntc_ws_encode(NTC_WS_CLOSE, NULL, 0, cf, sizeof cf);
    if (cn > 0) {
        c->stream_ended = true; /* on_writable closes once the close frame drains */
        (void)stream_push(g, c, cf, (size_t)cn);
    } else {
        conn_close(g, c);
    }
}

/* client -> controller: read available bytes, decode complete frames, and relay
 * data messages to the controller (ping/close handled here). <0 if conn closed. */
static int on_ws_readable(gateway *g, conn *c) {
    for (;;) {
        if (c->rlen == NTC_CONN_RBUF) { conn_close(g, c); return -1; } /* frame too big to buffer */
        ssize_t n = recv(c->fd, c->rbuf + c->rlen, NTC_CONN_RBUF - c->rlen, 0);
        if (n > 0) { c->rlen += (size_t)n; continue; }
        if (n == 0) { conn_close(g, c); return -1; } /* client EOF */
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        conn_close(g, c);
        return -1;
    }

    size_t off = 0;
    while (off < c->rlen) {
        size_t consumed = 0, paylen = 0;
        ntc_ws_opcode op; bool fin; uint8_t *pay;
        int r = ntc_ws_decode((uint8_t *)c->rbuf + off, c->rlen - off, &consumed, &op, &fin, &pay, &paylen);
        if (r == 0) break;                       /* need more bytes */
        if (r < 0) { conn_close(g, c); return -1; } /* protocol error */

        if (op == NTC_WS_CLOSE) {
            conn_close(g, c); /* notifies the controller via the is_ws path */
            return -1;
        } else if (op == NTC_WS_PING) {
            uint8_t pong[160];
            size_t pl = paylen > 125 ? 0 : paylen; /* control frames are <=125 */
            ssize_t pn = ntc_ws_encode(NTC_WS_PONG, pay, pl, pong, sizeof pong);
            if (pn > 0 && stream_push(g, c, pong, (size_t)pn) < 0) return -1;
        } else if (op == NTC_WS_PONG) {
            /* ignore */
        } else if (c->wait_ctrl && c->inflight) { /* TEXT / BINARY / CONT -> controller */
            uint8_t opcode = (op == NTC_WS_BIN) ? (uint8_t)NTC_WS_BIN : (uint8_t)NTC_WS_TEXT;
            size_t cap = paylen + 16;
            uint8_t *enc = malloc(cap);
            if (enc) {
                ssize_t pn = ntc_wire_encode_ws_msg(opcode, ntc_slice_new((const char *)pay, paylen), enc, cap);
                if (pn > 0 && ctrl_queue(c->wait_ctrl, NTC_MSG_WS_MSG, c->req_id, enc, (uint32_t)pn) == 0)
                    (void)ctrl_update_poll(g, c->wait_ctrl);
                free(enc);
            }
        }
        off += consumed;
    }
    if (off > 0) { memmove(c->rbuf, c->rbuf + off, c->rlen - off); c->rlen -= off; }
    return 0;
}

/* Perform the WebSocket upgrade handshake and wire the conn to the controller. */
static int gw_ws_upgrade(gateway *g, conn *c, const ntc_request *req, service *svc) {
    if (c->tls) /* wss (WS over TLS) inbound framing is not wired yet (see PROBLEMS.md) */
        return respond_and_flush(g, c, 400, NTC_SLICE_LIT("{\"error\":\"wss not supported yet\"}"));
    if (svc->disabled || !svc->conn)
        return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"service unavailable\"}"));
    ntc_slice key = ntc_http_header(req, "sec-websocket-key");
    if (key.len == 0 || key.len > 64)
        return respond_and_flush(g, c, 400, NTC_SLICE_LIT("{\"error\":\"missing Sec-WebSocket-Key\"}"));
    char accept[40];
    ntc_ws_accept_key(key.ptr, key.len, accept, sizeof accept);

    uint8_t *enc = malloc(NTC_CONN_RBUF + 1024);
    if (!enc) return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"oom\"}"));
    ssize_t pl = ntc_wire_encode_request(req, enc, NTC_CONN_RBUF + 1024);
    if (pl < 0) { free(enc); return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"encode failed\"}")); }
    uint32_t id;
    if (gw_alloc_id(g, c, &id) != 0) { free(enc); return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"too many in-flight\"}")); }
    if (ctrl_queue(svc->conn, NTC_MSG_WS_OPEN, id, enc, (uint32_t)pl) != 0) {
        free(enc); gw_free_slot(g, (uint16_t)(id & NTC_INFLIGHT_MASK));
        return respond_and_flush(g, c, 503, NTC_SLICE_LIT("{\"error\":\"queue full\"}"));
    }
    free(enc);
    (void)ctrl_update_poll(g, svc->conn);

    c->req_id = id;
    c->inflight = true;
    c->wait_ctrl = svc->conn;
    c->is_ws = true;
    c->streaming = true;       /* reuse the swbuf outbound-drain machinery */
    c->stream_head_sent = true;
    c->state = CS_WS;
    c->rlen = 0;               /* the HTTP request is consumed; rbuf now holds WS frames */
    if (!c->is_admin && !c->logged && g->mw) {
        ntc_mw_after(g->mw, c->log_method, c->log_path, c->request_id, 101, now_ms() - c->req_start);
        c->logged = true;
    }

    char head[256];
    int hn = snprintf(head, sizeof head,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    if (hn < 0) { conn_close(g, c); return -1; }
    return stream_push(g, c, head, (size_t)hn);
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
        if (c->stream_head_sent) /* mid-stream: can't inject a 502 into an open body */
            conn_close(g, c);
        else
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
        switch (h.type) {
            case NTC_MSG_RESPONSE:       gw_deliver(g, h.request_id, pl, h.length); break;
            case NTC_MSG_RESPONSE_BEGIN: gw_deliver_begin(g, h.request_id, pl, h.length); break;
            case NTC_MSG_RESPONSE_CHUNK: gw_deliver_chunk(g, h.request_id, pl, h.length); break;
            case NTC_MSG_RESPONSE_END:   gw_deliver_end(g, h.request_id); break;
            case NTC_MSG_WS_MSG:         gw_ws_deliver(g, h.request_id, pl, h.length); break;
            case NTC_MSG_WS_CLOSE:       gw_ws_deliver_close(g, h.request_id); break;
            default: break;
        }
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
    if (svc->disabled || !svc->conn)
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

static const char *mime_for(const char *path) {
    const char *d = strrchr(path, '.');
    if (!d) return "application/octet-stream";
    if (!strcmp(d, ".html") || !strcmp(d, ".htm")) return "text/html; charset=utf-8";
    if (!strcmp(d, ".css")) return "text/css";
    if (!strcmp(d, ".js") || !strcmp(d, ".mjs")) return "application/javascript";
    if (!strcmp(d, ".json")) return "application/json";
    if (!strcmp(d, ".svg")) return "image/svg+xml";
    if (!strcmp(d, ".png")) return "image/png";
    if (!strcmp(d, ".jpg") || !strcmp(d, ".jpeg")) return "image/jpeg";
    if (!strcmp(d, ".ico")) return "image/x-icon";
    if (!strcmp(d, ".txt")) return "text/plain; charset=utf-8";
    if (!strcmp(d, ".wasm")) return "application/wasm";
    return "application/octet-stream";
}

/* 2 = not served (fall through); 0/-1 = served (alive/closed). */
static int serve_static(gateway *g, conn *c, const ntc_request *req) {
    if (!g->static_dir[0] || !ntc_slice_eq_cstr(req->method, "GET")) return 2;

    char rel[512];
    if (req->path.len <= 1) {
        snprintf(rel, sizeof rel, "index.html");
    } else {
        const char *p = req->path.ptr + 1;
        size_t n = req->path.len - 1;
        if (n >= sizeof rel - 12) return 2;
        for (size_t i = 0; i < n; i++)
            if (p[i] == '\0' || (p[i] == '.' && i + 1 < n && p[i + 1] == '.')) return 2; /* no traversal */
        memcpy(rel, p, n);
        rel[n] = '\0';
        if (rel[n - 1] == '/') snprintf(rel + n, sizeof rel - n, "index.html");
    }

    char full[800];
    snprintf(full, sizeof full, "%s/%s", g->static_dir, rel);
    int fd = open(full, O_RDONLY);
    if (fd < 0) return 2;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > 10 * 1024 * 1024) { close(fd); return 2; }
    size_t sz = (size_t)st.st_size;
    char *buf = ntc_arena_alloc(&c->arena, sz ? sz : 1);
    if (!buf) { close(fd); return 2; }
    size_t got = 0;
    while (got < sz) { ssize_t r = read(fd, buf + got, sz - got); if (r <= 0) break; got += (size_t)r; }
    close(fd);
    if (got != sz) return 2;
    return send_resp(g, c, 200, ntc_slice_cstr(mime_for(rel)), ntc_slice_new(buf, sz));
}

/* Generate a basic OpenAPI 3.0 spec from the registry routes. */
static int serve_openapi(gateway *g, conn *c) {
    ntc_route_row rows[256];
    size_t n = 0;
    (void)ntc_registry_list_routes(g->reg, rows, 256, &n);
    size_t cap = 64 * 1024;
    char *buf = ntc_arena_alloc(&c->arena, cap);
    if (!buf) return send_resp(g, c, 500, JSON, NTC_SLICE_LIT("{}"));
    size_t off = (size_t)snprintf(buf, cap,
        "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"%s\",\"version\":\"%s\"},\"paths\":{",
        g->app_name, NTC_VERSION);
    for (size_t i = 0; i < n && off < cap - 512; i++) {
        char path[160];
        size_t pj = 0, plen = strlen(rows[i].pattern);
        for (size_t k = 0; k < plen && pj < sizeof path - 2; k++) {
            if (rows[i].pattern[k] == ':') {           /* :id -> {id} */
                path[pj++] = '{';
                k++;
                while (k < plen && rows[i].pattern[k] != '/' && pj < sizeof path - 2) path[pj++] = rows[i].pattern[k++];
                path[pj++] = '}';
                k--;
            } else {
                path[pj++] = rows[i].pattern[k];
            }
        }
        path[pj] = '\0';
        char m[8];
        snprintf(m, sizeof m, "%s", rows[i].method);
        for (char *q = m; *q; q++) *q = (char)tolower((unsigned char)*q);
        off += (size_t)snprintf(buf + off, cap - off,
            "%s\"%s\":{\"%s\":{\"summary\":\"-> %s\",\"responses\":{\"200\":{\"description\":\"OK\"}}}}",
            i ? "," : "", path, m, rows[i].service);
    }
    off += (size_t)snprintf(buf + off, cap - off, "}}");
    return send_resp(g, c, 200, JSON, ntc_slice_new(buf, off));
}

/* ---- OAuth2 login (auth-code + PKCE) + sessions ---- */

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int url_encode(const char *s, char *out, size_t cap) {
    static const char *hex = "0123456789ABCDEF";
    size_t o = 0;
    for (; *s && o + 4 < cap; s++) {
        unsigned char ch = (unsigned char)*s;
        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') out[o++] = (char)ch;
        else { out[o++] = '%'; out[o++] = hex[ch >> 4]; out[o++] = hex[ch & 15]; }
    }
    if (o < cap) out[o] = '\0';
    return (int)o;
}

static void url_decode(char *s) {
    char *o = s;
    for (char *p = s; *p; p++) {
        if (*p == '%' && p[1] && p[2]) {
            int hi = hexval((unsigned char)p[1]), lo = hexval((unsigned char)p[2]);
            if (hi >= 0 && lo >= 0) { *o++ = (char)(hi * 16 + lo); p += 2; continue; }
        }
        if (*p == '+') { *o++ = ' '; continue; }
        *o++ = *p;
    }
    *o = '\0';
}

static bool query_get(ntc_slice q, const char *key, char *out, size_t cap) {
    size_t klen = strlen(key);
    const char *p = q.ptr, *end = q.ptr + q.len;
    while (p && p < end) {
        const char *amp = memchr(p, '&', (size_t)(end - p));
        const char *seg_end = amp ? amp : end;
        if ((size_t)(seg_end - p) > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            size_t vl = (size_t)(seg_end - v);
            if (vl >= cap) vl = cap - 1;
            memcpy(out, v, vl);
            out[vl] = '\0';
            return true;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return false;
}

/* 302 to `location`, optionally setting a cookie. Reuses c->extra_headers. */
static int oauth_redirect(gateway *g, conn *c, const char *location, const char *set_cookie) {
    size_t n = (size_t)snprintf(c->extra_headers, sizeof c->extra_headers, "Location: %s\r\n", location);
    if (set_cookie && n < sizeof c->extra_headers)
        (void)snprintf(c->extra_headers + n, sizeof c->extra_headers - n, "Set-Cookie: %s\r\n", set_cookie);
    return send_resp(g, c, 302, NTC_SLICE_LIT("text/html; charset=utf-8"),
                     NTC_SLICE_LIT("<a href=\"/\">redirecting</a>"));
}

static int handle_oauth(gateway *g, conn *c, const ntc_request *req) {
    long now = time(NULL);

    if (ntc_slice_eq_cstr(req->path, "/auth/login")) {
        char state[40], verifier[64], challenge[64];
        if (!ntc_random_token(state, sizeof state, 16) ||
            !ntc_pkce_verifier(verifier, sizeof verifier) ||
            !ntc_pkce_challenge(verifier, challenge, sizeof challenge))
            return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"pkce\"}"));
        ntc_kv_put(g->oauth_pending, state, verifier, now + 600); /* 10 min to complete */
        char er[400], es[200];
        url_encode(g->oauth_redirect_uri, er, sizeof er);
        url_encode(g->oauth_scopes[0] ? g->oauth_scopes : "openid", es, sizeof es);
        char loc[1000];
        snprintf(loc, sizeof loc,
            "%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s"
            "&state=%s&code_challenge=%s&code_challenge_method=S256",
            g->oauth_authorize_url, g->oauth_client_id, er, es, state, challenge);
        return oauth_redirect(g, c, loc, NULL);
    }

    if (ntc_slice_eq_cstr(req->path, "/auth/callback")) {
        char code[512] = "", state[64] = "", verifier[64];
        query_get(req->query, "code", code, sizeof code);
        query_get(req->query, "state", state, sizeof state);
        url_decode(code); url_decode(state);
        if (!code[0] || !state[0] || !ntc_kv_get(g->oauth_pending, state, now, verifier, sizeof verifier))
            return respond_and_flush(g, c, 400, NTC_SLICE_LIT("{\"error\":\"invalid or expired state\"}"));
        ntc_kv_del(g->oauth_pending, state);

        char er[400], ec[600];
        url_encode(g->oauth_redirect_uri, er, sizeof er);
        url_encode(code, ec, sizeof ec);
        char body[1800];
        int bn = snprintf(body, sizeof body,
            "grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
            ec, er, g->oauth_client_id, verifier);
        if (g->oauth_client_secret[0] && bn > 0 && (size_t)bn < sizeof body) {
            char esec[400];
            url_encode(g->oauth_client_secret, esec, sizeof esec);
            bn += snprintf(body + bn, sizeof body - (size_t)bn, "&client_secret=%s", esec);
        }

        char resp[8192], err[80];
        int rn = ntc_https_post(g->oauth_ca, g->oauth_token_url, "application/x-www-form-urlencoded",
                                body, (size_t)bn, resp, sizeof resp, 5000, err, sizeof err);
        if (rn <= 0) {
            NTC_WARN("oauth: token exchange failed: %s", err);
            return respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"token exchange failed\"}"));
        }

        char sub[128] = "", scope[256] = "";
        bool ok = false;
        ntc_arena a;
        if (ntc_arena_init(&a, 16384) == NTC_OK) {
            ntc_json *root = ntc_json_parse(&a, resp, (size_t)rn);
            ntc_slice idt = root ? ntc_json_str(ntc_json_get(root, "id_token")) : ntc_slice_new(NULL, 0);
            if (idt.len && g->oauth_client_secret[0]) {
                /* OIDC permits HS256 id_tokens signed with the client secret. */
                ntc_jwt_claims cl;
                if (ntc_jwt_verify_hs256(idt.ptr, idt.len, g->oauth_client_secret, now, &cl)) {
                    snprintf(sub, sizeof sub, "%s", cl.sub);
                    snprintf(scope, sizeof scope, "%s", cl.scope);
                    ok = true;
                }
            }
            ntc_arena_destroy(&a);
        }
        if (!ok) return respond_and_flush(g, c, 401, NTC_SLICE_LIT("{\"error\":\"invalid id_token\"}"));

        char sid[80], val[400];
        if (!ntc_random_token(sid, sizeof sid, 24))
            return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"sid\"}"));
        snprintf(val, sizeof val, "%s\t%s", sub, scope);
        ntc_kv_put(g->sessions, sid, val, now + 8 * 3600);
        char cookie[256];
        ntc_cookie_format(cookie, sizeof cookie, "ntc_session", sid, c->tls != NULL, 8 * 3600);
        return oauth_redirect(g, c, g->oauth_success[0] ? g->oauth_success : "/", cookie);
    }

    if (ntc_slice_eq_cstr(req->path, "/auth/logout")) {
        ntc_slice ck = ntc_http_header(req, "cookie");
        if (ck.len) {
            char ckbuf[1024];
            size_t cl = ck.len < sizeof ckbuf - 1 ? ck.len : sizeof ckbuf - 1;
            memcpy(ckbuf, ck.ptr, cl); ckbuf[cl] = '\0';
            char sid[80];
            if (ntc_cookie_get(ckbuf, "ntc_session", sid, sizeof sid)) ntc_kv_del(g->sessions, sid);
        }
        char cookie[256];
        ntc_cookie_format(cookie, sizeof cookie, "ntc_session", "", c->tls != NULL, 0); /* expire */
        return oauth_redirect(g, c, g->oauth_success[0] ? g->oauth_success : "/", cookie);
    }

    return respond_and_flush(g, c, 404, NTC_SLICE_LIT("{\"error\":\"not found\"}"));
}

static int gw_dispatch(gateway *g, conn *c, const ntc_request *req) {
    if (g->oauth_enabled && ntc_slice_starts_with(req->path, NTC_SLICE_LIT("/auth/")))
        return handle_oauth(g, c, req);
    /* reserved framework namespace - never overridable by user routes */
    if (ntc_slice_starts_with(req->path, NTC_SLICE_LIT("/_ntc/"))) {
        if (ntc_slice_eq_cstr(req->path, "/_ntc/health"))
            return send_resp(g, c, 200, JSON, NTC_SLICE_LIT("{\"status\":\"ok\"}"));
        if (ntc_slice_eq_cstr(req->path, "/_ntc/ready"))
            return send_resp(g, c, 200, JSON, NTC_SLICE_LIT("{\"status\":\"ready\"}"));
        if (ntc_slice_eq_cstr(req->path, "/_ntc/openapi.json"))
            return serve_openapi(g, c);
        return send_resp(g, c, 404, JSON, NTC_SLICE_LIT("{\"error\":\"not found\"}"));
    }

    ntc_handler h = NULL;
    void *udata = NULL;
    ntc_route_params params;
    ntc_route_status rs = ntc_router_match(g->router, req->method, req->path, &h, &udata, &params);

    if (rs == NTC_ROUTE_NOT_FOUND) {
        /* try static files before falling back */
        int sr = serve_static(g, c, req);
        if (sr != 2) return sr;
        /* friendly landing on "/" when no user route claims it */
        if (ntc_slice_eq_cstr(req->path, "/")) {
            char *buf = ntc_arena_alloc(&c->arena, 1024);
            if (buf) {
                long up = (now_ms() - g->m.start_ms) / 1000;
                int m = snprintf(buf, 1024,
                    "<!doctype html><meta charset=utf-8><title>%s</title>"
                    "<body style='font-family:system-ui;background:#0e1116;color:#e6edf3;"
                    "display:flex;height:90vh;align-items:center;justify-content:center;flex-direction:column'>"
                    "<h1 style='margin:0'>%s</h1>"
                    "<p style='color:#9aa7b3'>powered by naitron-c &middot; core uptime %lds</p></body>",
                    g->app_name, g->app_name, up);
                if (m > 0)
                    return send_resp(g, c, 200, NTC_SLICE_LIT("text/html; charset=utf-8"),
                                     ntc_slice_new(buf, (size_t)m));
            }
        }
        return respond_and_flush(g, c, 404, NTC_SLICE_LIT("{\"error\":\"not found\"}"));
    }
    if (rs == NTC_ROUTE_METHOD_NOT_ALLOWED)
        return respond_and_flush(g, c, 405, NTC_SLICE_LIT("{\"error\":\"method not allowed\"}"));
    if (h == forward_marker) {
        g->m.forwarded++;
        /* enrich the forwarded request with path params + auth identity */
        ntc_request fr = *req;
        fr.nparams = params.count < NTC_MAX_PARAMS ? params.count : NTC_MAX_PARAMS;
        for (size_t i = 0; i < fr.nparams; i++) {
            fr.params[i].name = params.items[i].name;
            fr.params[i].value = params.items[i].value;
        }
        fr.auth_sub = ntc_slice_cstr(c->auth_sub);
        fr.auth_scope = ntc_slice_cstr(c->auth_scope);
        /* a WebSocket upgrade request takes the WS path instead of HTTP forward */
        if (ntc_slice_eq_cstr(ntc_http_header(&fr, "upgrade"), "websocket"))
            return gw_ws_upgrade(g, c, &fr, (service *)udata);
        return gw_forward(g, c, &fr, (service *)udata);
    }

    g->m.builtin++;
    ntc_response res = { .status = 200, .content_type = JSON, .body = NTC_SLICE_LIT("") };
    if (h(req, &params, &res, &c->arena, udata) != 0)
        return respond_and_flush(g, c, 500, NTC_SLICE_LIT("{\"error\":\"internal error\"}"));
    rec_status(g, res.status);
    if (conn_respond(c, res.status, res.content_type, res.body) != 0) { conn_close(g, c); return -1; }
    return conn_flush(g, c);
}

/* ---- admin endpoint: read-only dashboard + stats (localhost) ---- */
static const char *DASHBOARD_HTML =
"<!doctype html>\n"
"<html lang='en'><head><meta charset='utf-8'>\n"
"<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
"<title>naitron-c</title><style>\n"
"*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#0e1116;color:#e6edf3}\n"
"header{padding:16px 24px;border-bottom:1px solid #222b36;display:flex;align-items:center;gap:12px}\n"
"header h1{font-size:18px;margin:0;font-weight:600}.dot{width:9px;height:9px;border-radius:50%;background:#2ea043;box-shadow:0 0 8px #2ea043}\n"
".tabs{display:flex;gap:4px;padding:12px 24px 0}.tab{padding:8px 16px;border:none;background:none;color:#9aa7b3;cursor:pointer;border-radius:8px 8px 0 0;font-size:14px}\n"
".tab.active{color:#e6edf3;background:#161b22}main{padding:24px}\n"
".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}\n"
".card{background:#161b22;border:1px solid #222b36;border-radius:12px;padding:16px}.card .k{color:#9aa7b3;font-size:12px;text-transform:uppercase;letter-spacing:.5px}.card .v{font-size:28px;font-weight:700;margin-top:6px}\n"
"table{width:100%;border-collapse:collapse;background:#161b22;border-radius:12px;overflow:hidden}th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #222b36;font-size:13px}th{color:#9aa7b3;font-weight:600}\n"
".pill{padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600}.up{background:#13351f;color:#3fb950}.down{background:#3d1d1d;color:#f85149}.disabled{background:#2a2f37;color:#9aa7b3}\n"
".hidden{display:none}.muted{color:#9aa7b3}\n"
"</style></head><body>\n"
"<header><span class='dot'></span><h1>naitron-c</h1><span class='muted' id='sub'>dashboard</span></header>\n"
"<div class='tabs'><button class='tab active' data-t='overview'>Overview</button>"
"<button class='tab' data-t='services'>Services</button><button class='tab' data-t='routes'>Routes</button></div>\n"
"<main>\n"
" <section id='overview'><div class='grid' id='stats'></div></section>\n"
" <section id='services' class='hidden'><table><thead><tr><th>Service</th><th>Status</th><th>Binary</th><th>Restarts</th><th>Uptime</th></tr></thead><tbody id='svcbody'></tbody></table></section>\n"
" <section id='routes' class='hidden'><table><thead><tr><th>Method</th><th>Pattern</th><th>Service</th></tr></thead><tbody id='rtbody'></tbody></table></section>\n"
"</main><script>\n"
"const $=s=>document.querySelector(s);\n"
"document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');['overview','services','routes'].forEach(id=>$('#'+id).classList.toggle('hidden',id!==b.dataset.t));});\n"
"function fu(s){if(s<60)return s+'s';if(s<3600)return (s/60|0)+'m';return (s/3600|0)+'h '+((s%3600)/60|0)+'m';}\n"
"async function tick(){try{\n"
" const s=await (await fetch('/api/stats')).json();\n"
" $('#sub').textContent=s.backend+' \\u00b7 up '+fu(s.uptime_s);\n"
" const c=[['Requests',s.requests_total],['2xx',s.status_2xx],['4xx',s.status_4xx],['5xx',s.status_5xx],['Forwarded',s.forwarded],['Built-in',s.builtin],['Services',s.services],['Routes',s.routes]];\n"
" $('#stats').innerHTML=c.map(x=>`<div class='card'><div class='k'>${x[0]}</div><div class='v'>${x[1]}</div></div>`).join('');\n"
" const sv=await (await fetch('/api/services')).json();\n"
" $('#svcbody').innerHTML=sv.length?sv.map(x=>`<tr><td>${x.name}</td><td><span class='pill ${x.status}'>${x.status}</span></td><td class='muted'>${x.bin}</td><td>${x.restarts}</td><td>${x.status==='up'?fu(x.uptime_s):'-'}</td></tr>`).join(''):`<tr><td colspan=5 class='muted'>no services</td></tr>`;\n"
" const rt=await (await fetch('/api/routes')).json();\n"
" $('#rtbody').innerHTML=rt.length?rt.map(x=>`<tr><td>${x.method}</td><td>${x.pattern}</td><td>${x.service}</td></tr>`).join(''):`<tr><td colspan=3 class='muted'>no routes</td></tr>`;\n"
" }catch(e){$('#sub').textContent='disconnected';}}\n"
"tick();setInterval(tick,1500);\n"
"</script></body></html>\n";

static void incore_mcp_exec(void *ctx, const char *command, char *out, size_t cap) {
    gateway *g = ctx;
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", command);
    exec_control_command(g, buf, out, cap);
}

static int handle_admin(gateway *g, conn *c, const ntc_request *req) {
    /* MCP over HTTP (console port = localhost, token-authenticated) */
    if (ntc_slice_eq_cstr(req->path, "/_ntc/mcp")) {
        if (!ntc_slice_eq_cstr(req->method, "POST"))
            return send_resp(g, c, 405, JSON, NTC_SLICE_LIT("{\"error\":\"POST only\"}"));
        ntc_slice auth = ntc_http_header(req, "authorization");
        bool ok = auth.len > 7 && memcmp(auth.ptr, "Bearer ", 7) == 0 &&
                  ntc_slice_eq_cstr(ntc_slice_new(auth.ptr + 7, auth.len - 7), g->token);
        if (!ok) return send_resp(g, c, 401, JSON, NTC_SLICE_LIT("{\"error\":\"unauthorized\"}"));
        char *out = ntc_arena_alloc(&c->arena, 32 * 1024);
        if (!out) return send_resp(g, c, 500, JSON, NTC_SLICE_LIT("{}"));
        ntc_mcp_handle(req->body.ptr, req->body.len, incore_mcp_exec, g, out, 32 * 1024);
        if (out[0] == '\0') return send_resp(g, c, 202, JSON, NTC_SLICE_LIT(""));
        return send_resp(g, c, 200, JSON, ntc_slice_new(out, strlen(out)));
    }

    if (!ntc_slice_eq_cstr(req->method, "GET"))
        return send_resp(g, c, 405, JSON, NTC_SLICE_LIT("{\"error\":\"method not allowed\"}"));

    if (ntc_slice_eq_cstr(req->path, "/") || ntc_slice_eq_cstr(req->path, "/index.html"))
        return send_resp(g, c, 200, NTC_SLICE_LIT("text/html; charset=utf-8"),
                          ntc_slice_cstr(DASHBOARD_HTML));

    if (ntc_slice_eq_cstr(req->path, "/api/stats")) {
        char *buf = ntc_arena_alloc(&c->arena, 1024);
        if (!buf) return send_resp(g, c, 500, JSON, NTC_SLICE_LIT("{}"));
        long up = (now_ms() - g->m.start_ms) / 1000;
        int m = snprintf(buf, 1024,
            "{\"uptime_s\":%ld,\"requests_total\":%llu,\"status_2xx\":%llu,\"status_4xx\":%llu,"
            "\"status_5xx\":%llu,\"forwarded\":%llu,\"builtin\":%llu,\"services\":%zu,"
            "\"routes\":%zu,\"backend\":\"%s\",\"inflight_cap\":%u}",
            up, (unsigned long long)g->m.requests_total, (unsigned long long)g->m.status_2xx,
            (unsigned long long)g->m.status_4xx, (unsigned long long)g->m.status_5xx,
            (unsigned long long)g->m.forwarded, (unsigned long long)g->m.builtin,
            g->nservices, ntc_router_count(g->router), ntc_poller_backend(), NTC_MAX_INFLIGHT);
        return send_resp(g, c, 200, JSON, ntc_slice_new(buf, (size_t)(m < 0 ? 0 : m)));
    }

    if (ntc_slice_eq_cstr(req->path, "/api/services")) {
        size_t cap = 64 * 1024;
        char *buf = ntc_arena_alloc(&c->arena, cap);
        if (!buf) return send_resp(g, c, 500, JSON, NTC_SLICE_LIT("[]"));
        long t = now_ms();
        size_t off = (size_t)snprintf(buf, cap, "[");
        for (size_t i = 0; i < g->nservices && off < cap - 512; i++) {
            service *svc = &g->services[i];
            const char *st = svc->disabled ? "disabled" : (svc->conn ? "up" : "down");
            long up = svc->conn ? (t - svc->spawned_at) / 1000 : 0;
            off += (size_t)snprintf(buf + off, cap - off,
                "%s{\"name\":\"%s\",\"bin\":\"%s\",\"status\":\"%s\",\"restarts\":%d,\"uptime_s\":%ld}",
                i ? "," : "", svc->name, svc->bin, st, svc->restart_count, up);
        }
        off += (size_t)snprintf(buf + off, cap - off, "]");
        return send_resp(g, c, 200, JSON, ntc_slice_new(buf, off));
    }

    if (ntc_slice_eq_cstr(req->path, "/api/routes")) {
        ntc_route_row rows[256]; size_t n = 0;
        (void)ntc_registry_list_routes(g->reg, rows, 256, &n);
        size_t cap = 64 * 1024;
        char *buf = ntc_arena_alloc(&c->arena, cap);
        if (!buf) return send_resp(g, c, 500, JSON, NTC_SLICE_LIT("[]"));
        size_t off = (size_t)snprintf(buf, cap, "[");
        for (size_t i = 0; i < n && off < cap - 512; i++)
            off += (size_t)snprintf(buf + off, cap - off,
                "%s{\"method\":\"%s\",\"pattern\":\"%s\",\"service\":\"%s\"}",
                i ? "," : "", rows[i].method, rows[i].pattern, rows[i].service);
        off += (size_t)snprintf(buf + off, cap - off, "]");
        return send_resp(g, c, 200, JSON, ntc_slice_new(buf, off));
    }

    if (ntc_slice_eq_cstr(req->path, "/_ntc/metrics") || ntc_slice_eq_cstr(req->path, "/metrics")) {
        char *buf = ntc_arena_alloc(&c->arena, 2048);
        if (!buf) return send_resp(g, c, 500, JSON, NTC_SLICE_LIT("{}"));
        long up = (now_ms() - g->m.start_ms) / 1000;
        int m = snprintf(buf, 2048,
            "# HELP ntc_requests_total total HTTP requests\n# TYPE ntc_requests_total counter\n"
            "ntc_requests_total %llu\n"
            "ntc_responses_total{class=\"2xx\"} %llu\n"
            "ntc_responses_total{class=\"4xx\"} %llu\n"
            "ntc_responses_total{class=\"5xx\"} %llu\n"
            "ntc_forwarded_total %llu\nntc_builtin_total %llu\n"
            "ntc_services %zu\nntc_uptime_seconds %ld\n",
            (unsigned long long)g->m.requests_total, (unsigned long long)g->m.status_2xx,
            (unsigned long long)g->m.status_4xx, (unsigned long long)g->m.status_5xx,
            (unsigned long long)g->m.forwarded, (unsigned long long)g->m.builtin,
            g->nservices, up);
        return send_resp(g, c, 200, NTC_SLICE_LIT("text/plain; version=0.0.4"),
                         ntc_slice_new(buf, (size_t)(m < 0 ? 0 : m)));
    }

    return send_resp(g, c, 404, JSON, NTC_SLICE_LIT("{\"error\":\"not found\"}"));
}

/* Parse whatever is buffered in c->rbuf and run the middleware + dispatch. The
 * transport (recv() or TLS) fills c->rbuf first; `eof` means end-of-stream.
 * Returns <0 if the connection was closed - the caller must stop touching it. */
static int process_request(gateway *g, conn *c, bool eof) {
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

    /* middleware before-chain (main conns): request-id, CORS, rate-limit */
    if (!c->is_admin) {
        size_t ml = req.method.len < sizeof c->log_method - 1 ? req.method.len : sizeof c->log_method - 1;
        memcpy(c->log_method, req.method.ptr, ml); c->log_method[ml] = '\0';
        size_t pl = req.path.len < sizeof c->log_path - 1 ? req.path.len : sizeof c->log_path - 1;
        memcpy(c->log_path, req.path.ptr, pl); c->log_path[pl] = '\0';
        /* resolve a session cookie (OAuth login) -> pre-authenticated identity */
        bool pre_authed = false;
        char sess_sub[128] = "", sess_scope[256] = "";
        if (g->sessions) {
            ntc_slice ck = ntc_http_header(&req, "cookie");
            if (ck.len) {
                char ckbuf[1024];
                size_t cl = ck.len < sizeof ckbuf - 1 ? ck.len : sizeof ckbuf - 1;
                memcpy(ckbuf, ck.ptr, cl); ckbuf[cl] = '\0';
                char sid[80], val[400];
                if (ntc_cookie_get(ckbuf, "ntc_session", sid, sizeof sid) &&
                    ntc_kv_get(g->sessions, sid, time(NULL), val, sizeof val)) {
                    char *tab = strchr(val, '\t');
                    if (tab) { *tab = '\0'; snprintf(sess_scope, sizeof sess_scope, "%s", tab + 1); }
                    snprintf(sess_sub, sizeof sess_sub, "%s", val);
                    pre_authed = true;
                }
            }
        }
        if (g->mw) {
            ntc_mw_result r;
            bool sc = ntc_mw_before(g->mw, &req, c->client_ip, now_ms(), pre_authed, &r);
            snprintf(c->extra_headers, sizeof c->extra_headers, "%s", r.extra_headers);
            snprintf(c->request_id, sizeof c->request_id, "%s", r.request_id);
            if (pre_authed) {
                snprintf(c->auth_sub, sizeof c->auth_sub, "%s", sess_sub);
                snprintf(c->auth_scope, sizeof c->auth_scope, "%s", sess_scope);
            } else {
                snprintf(c->auth_sub, sizeof c->auth_sub, "%s", r.auth_sub);
                snprintf(c->auth_scope, sizeof c->auth_scope, "%s", r.auth_scope);
            }
            if (sc) { rec_status(g, r.status); return send_resp(g, c, r.status, r.content_type, r.body); }
        }
    }
    return c->is_admin ? handle_admin(g, c, &req) : gw_dispatch(g, c, &req);
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
    return process_request(g, c, eof);
}

/* ---- TLS connection driver ----
 * A TLS conn is driven by a single handler on any readable/writable event.
 * ntc_tls_pump_socket() moves encrypted bytes both ways (and runs the
 * handshake); we then feed decrypted bytes to the HTTP layer and encrypt the
 * response back through the engine. The plaintext path above is untouched. */

static int tls_set_interest(gateway *g, conn *c) {
    uint32_t ev = NTC_POLL_READ;
    if (ntc_tls_wants_write(c->tls)) ev |= NTC_POLL_WRITE;
    if (c->state == CS_WRITE && c->wsent < c->wlen) ev |= NTC_POLL_WRITE;
    if (c->state == CS_STREAM && c->swsent < c->swlen) ev |= NTC_POLL_WRITE;
    if (ntc_poller_mod(g->p, c->fd, ev, c) != NTC_OK) { conn_close(g, c); return -1; }
    return 0;
}

/* Push the active write buffer (atomic c->wbuf, or the streaming c->swbuf)
 * through the engine and out to the socket. For a stream, records are flushed
 * after each drain (so events arrive incrementally) and the connection is only
 * closed at RESPONSE_END. Returns <0 if the connection was closed. */
static int tls_drive_write(gateway *g, conn *c) {
    bool streaming = c->streaming;
    for (;;) {
        const uint8_t *buf = streaming ? c->swbuf : (const uint8_t *)c->wbuf;
        size_t *sent = streaming ? &c->swsent : &c->wsent;
        size_t len = streaming ? c->swlen : c->wlen;
        size_t before = *sent;
        while (*sent < len) {
            int n = ntc_tls_send(c->tls, buf + *sent, len - *sent);
            if (n <= 0) break;
            *sent += (size_t)n;
        }
        bool done = (*sent >= len);
        if (done) {
            ntc_tls_flush(c->tls); /* emit records now (incremental SSE) */
            if (!streaming || c->stream_ended) ntc_tls_close_notify(c->tls);
        }
        if (ntc_tls_pump_socket(c->tls, c->fd) < 0) { conn_close(g, c); return -1; }
        if (ntc_tls_closed(c->tls)) { conn_close(g, c); return -1; }
        if (ntc_tls_wants_write(c->tls)) return 0;     /* socket full: await writable */
        if (done) {
            if (!streaming || c->stream_ended) { conn_close(g, c); return -1; } /* fully delivered */
            c->swlen = c->swsent = 0;                  /* stream drained, await next chunk */
            return 0;
        }
        if (*sent == before) return 0;                 /* no progress: avoid spin */
    }
}

/* Drain decrypted request bytes into c->rbuf, then parse + dispatch. */
static int tls_drive_read(gateway *g, conn *c) {
    bool got = false;
    while (c->rlen < sizeof c->rbuf) {
        int n = ntc_tls_recv(c->tls, c->rbuf + c->rlen, sizeof c->rbuf - c->rlen);
        if (n <= 0) break;
        c->rlen += (size_t)n; got = true;
    }
    bool eof = ntc_tls_closed(c->tls);
    if (!got && !eof) return 0; /* still handshaking or waiting for more */
    return process_request(g, c, eof);
}

static void on_tls_event(gateway *g, conn *c) {
    if (ntc_tls_pump_socket(c->tls, c->fd) < 0) { conn_close(g, c); return; }
    int rc = 0;
    if (c->state == CS_READ) {
        rc = tls_drive_read(g, c);
    } else if (c->state == CS_WAIT) {
        char tmp[256];
        while (ntc_tls_recv(c->tls, tmp, sizeof tmp) > 0) { } /* discard until response */
        if (ntc_tls_closed(c->tls)) { conn_close(g, c); return; }
    } else { /* CS_WRITE or CS_STREAM */
        rc = tls_drive_write(g, c); /* drains active buffer; detects client close */
    }
    if (rc < 0) return; /* conn closed by the drive */
    (void)tls_set_interest(g, c);
}

static void on_wait_readable(gateway *g, conn *c) {
    char tmp[256];
    ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
    if (n == 0) { conn_close(g, c); return; }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        conn_close(g, c);
}

static void accept_conns(gateway *g, int listen_fd, bool is_admin, bool is_tls) {
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int cfd = accept(listen_fd, (struct sockaddr *)&ss, &sl);
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
        c->is_admin = is_admin;
        if (is_tls) {
            c->tls = ntc_tls_new(g->tls_conf);
            if (!c->tls) { ntc_arena_destroy(&c->arena); close(cfd); free(c); continue; }
        }
        if (ss.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, c->client_ip, sizeof c->client_ip);
        else if (ss.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, c->client_ip, sizeof c->client_ip);
        if (ntc_poller_add(g->p, cfd, NTC_POLL_READ, c) != NTC_OK) {
            if (c->tls) ntc_tls_free(c->tls);
            ntc_arena_destroy(&c->arena); close(cfd); free(c);
        }
    }
}

static int make_admin_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* dashboard: localhost only */
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    if (listen(fd, 64) < 0) { close(fd); return -1; }
    if (set_nonblocking(fd) < 0) { close(fd); return -1; }
    return fd;
}

/* HTTPS listener: bound on all interfaces (a public-facing port, like the
 * plaintext gateway). */
static int make_tls_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    if (listen(fd, 256) < 0) { close(fd); return -1; }
    if (set_nonblocking(fd) < 0) { close(fd); return -1; }
    return fd;
}

/* ---- spawn + supervise ---- */
static int spawn_service(gateway *g, service *svc) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(sv[0]); close(sv[1]); return -1; }
    if (pid == 0) {
        /* child: keep only the controller socket; close every other inherited
         * fd so we don't hold the core's listener / control conns / sibling
         * controller sockets open (which would block their EOF). */
        char fdbuf[16];
        snprintf(fdbuf, sizeof fdbuf, "%d", sv[1]);
        setenv("NTC_CONTROLLER_FD", fdbuf, 1);
        int maxfd = 1024;
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY &&
            rl.rlim_cur < (rlim_t)maxfd)
            maxfd = (int)rl.rlim_cur;
        for (int i = 3; i < maxfd; i++)
            if (i != sv[1]) close(i);
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

/* ---- dev mode: mtime watch + hot reload ---- */

#define NTC_DEV_POLL_MS 400

static long long stat_mtime_ns(const struct stat *st) {
#if defined(__APPLE__)
    return (long long)st->st_mtimespec.tv_sec * 1000000000LL + st->st_mtimespec.tv_nsec;
#else
    return (long long)st->st_mtim.tv_sec * 1000000000LL + st->st_mtim.tv_nsec;
#endif
}

static long long path_mtime_ns(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return stat_mtime_ns(&st);
}

/* Greatest mtime among regular files under `path` (recursively), or the file's
 * own mtime if `path` is a file. Skips dotfiles and noisy build dirs so an
 * editor's churn in .git/build doesn't trip the watcher. Returns -1 if absent. */
static long long tree_max_mtime(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (S_ISREG(st.st_mode)) return stat_mtime_ns(&st);
    if (!S_ISDIR(st.st_mode)) return -1;
    DIR *d = opendir(path);
    if (!d) return -1;
    long long mx = -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue; /* skip ., .., dotfiles (.git) */
        if (strcmp(e->d_name, "build") == 0 || strcmp(e->d_name, "node_modules") == 0) continue;
        char child[1024];
        if ((size_t)snprintf(child, sizeof child, "%s/%s", path, e->d_name) >= sizeof child) continue;
        long long m = tree_max_mtime(child);
        if (m > mx) mx = m;
    }
    closedir(d);
    return mx;
}

/* Tear down a service's current process and schedule an immediate respawn. Unlike
 * controller_died this is intentional, so it neither logs an error nor applies
 * backoff; in-flight requests on the old process are failed (502 / truncate). */
static void dev_reload_service(gateway *g, service *svc) {
    if (svc->conn) {
        ctrl *ct = svc->conn;
        (void)ntc_poller_del(g->p, ct->fd);
        close(ct->fd);
        kill(ct->pid, SIGTERM);
        waitpid(ct->pid, NULL, 0);
        for (uint32_t i = 0; i < NTC_MAX_INFLIGHT; i++) {
            conn *c = g->pending[i];
            if (!c || c->wait_ctrl != ct) continue;
            gw_free_slot(g, (uint16_t)i);
            c->inflight = false;
            if (c->stream_head_sent) conn_close(g, c);
            else (void)respond_and_flush(g, c, 502, NTC_SLICE_LIT("{\"error\":\"reloading\"}"));
        }
        free(ct->rbuf); free(ct->wbuf); free(ct);
        svc->conn = NULL;
    }
    svc->backoff_ms = 0;
    svc->restart_at = now_ms(); /* supervise() respawns on the next tick */
}

/* Poll watched paths + controller binaries; rebuild and/or reload on change.
 * Self-throttled to NTC_DEV_POLL_MS so it can be called every loop iteration. */
static void dev_tick(gateway *g) {
    if (!g->dev_watch) return;
    long now = now_ms();
    if (g->dev_last_poll_ms && now - g->dev_last_poll_ms < NTC_DEV_POLL_MS) return;
    g->dev_last_poll_ms = now;

    /* 1. source watch -> optional build hook */
    bool changed = false;
    for (size_t i = 0; i < g->dev_npaths; i++) {
        long long m = tree_max_mtime(g->dev_paths[i]);
        if (m < 0) continue;
        if (g->dev_path_mtime[i] == 0) { g->dev_path_mtime[i] = m; continue; } /* first scan */
        if (m > g->dev_path_mtime[i]) { g->dev_path_mtime[i] = m; changed = true; }
    }
    if (changed && g->dev_build) {
        NTC_INFO("dev: source changed -> %s", g->dev_build);
        int rc = system(g->dev_build);
        if (rc != 0) NTC_WARN("dev: build exited %d (keeping current binaries)", rc);
        else NTC_SUCCESS("dev: build ok");
    }

    /* 2. binary watch -> reload the affected service (covers manual rebuilds too) */
    for (size_t i = 0; i < g->nservices; i++) {
        service *svc = &g->services[i];
        if (svc->disabled) continue;
        long long m = path_mtime_ns(svc->bin);
        if (m < 0) continue;
        if (svc->bin_mtime == 0) { svc->bin_mtime = m; continue; } /* first scan */
        if (m != svc->bin_mtime) {
            svc->bin_mtime = m;
            NTC_SUCCESS("dev: '%s' binary changed -> reloading", svc->name);
            dev_reload_service(g, svc);
        }
    }
}

static void supervise(gateway *g) {
    long t = now_ms();
    for (size_t i = 0; i < g->nservices; i++) {
        service *svc = &g->services[i];
        if (svc->disabled) continue;
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
        if (!g->services[i].disabled && !g->services[i].conn) {
            long d = g->services[i].restart_at - t;
            if (d < 0) d = 0;
            if (d < to) to = (int)d;
        }
    }
    if (g->dev_watch && to > NTC_DEV_POLL_MS) to = NTC_DEV_POLL_MS; /* wake to poll mtimes */
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
                /* NTC_CONTROLLER_ROUTE overrides the seeded route(s); accepts a
                 * ';'-separated list of "METHOD /path" entries so a quickstart
                 * controller can serve more than just GET /api/hello. */
                const char *routes = getenv("NTC_CONTROLLER_ROUTE");
                if (routes && *routes) {
                    char list[1024];
                    snprintf(list, sizeof list, "%s", routes);
                    for (char *save = NULL, *tok = strtok_r(list, ";", &save);
                         tok; tok = strtok_r(NULL, ";", &save)) {
                        char method[8] = "GET", path[256] = "";
                        if (sscanf(tok, "%7s %255s", method, path) >= 1 && path[0])
                            (void)ntc_registry_add_route(g->reg, method, path, "hello");
                    }
                } else {
                    (void)ntc_registry_add_route(g->reg, "GET", "/api/hello", "hello");
                    (void)ntc_registry_add_route(g->reg, "GET", "/api/hello/:name", "hello");
                }
                NTC_TRY(ntc_registry_list_services(g->reg, srows, 64, &scount));
            }
        }
    }
    if (scount == 0) return NTC_OK; /* built-ins only */
    if (scount > NTC_MAX_SERVICES) scount = NTC_MAX_SERVICES;

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

/* ---- control plane ---- */
static void gen_token(char *out, size_t cap) {
    unsigned char b[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, b, sizeof b) != (ssize_t)sizeof b) {
        snprintf(out, cap, "ntc-insecure-token");
        if (fd >= 0) close(fd);
        return;
    }
    close(fd);
    for (size_t i = 0; i < sizeof b && (2 * i + 2) < cap; i++)
        snprintf(out + 2 * i, cap - 2 * i, "%02x", b[i]);
}

static void load_token(gateway *g) {
    char buf[65]; bool found = false;
    if (ntc_registry_get_config(g->reg, "control_token", buf, sizeof buf, &found) == NTC_OK && found) {
        snprintf(g->token, sizeof g->token, "%s", buf);
    } else {
        gen_token(g->token, sizeof g->token);
        (void)ntc_registry_set_config(g->reg, "control_token", g->token);
    }
    const char *tf = getenv("NTC_TOKEN_FILE");
    if (!tf) tf = NTC_CONTROL_TOKEN_DEFAULT;
    int fd = open(tf, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t w = write(fd, g->token, strlen(g->token));
        (void)w;
        w = write(fd, "\n", 1);
        (void)w;
        close(fd);
    }
}

static int make_control_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&un, sizeof un) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    if (set_nonblocking(fd) < 0) { close(fd); return -1; }
    return fd;
}

static service *service_add_live(gateway *g, const char *name, const char *bin) {
    service *existing = find_service(g, name);
    if (existing) {
        free(existing->bin);
        existing->bin = strdup(bin);
        existing->disabled = false;
        return existing;
    }
    if (g->nservices >= NTC_MAX_SERVICES) return NULL;
    service *svc = &g->services[g->nservices];
    memset(svc, 0, sizeof *svc);
    svc->name = strdup(name);
    svc->bin = strdup(bin);
    svc->gw = g;
    svc->backoff_ms = NTC_BACKOFF_BASE;
    if (!svc->name || !svc->bin) { free(svc->name); free(svc->bin); return NULL; }
    g->nservices++;
    (void)spawn_service(g, svc);
    return svc;
}

/* Append a one-line response and close the control connection. */
static void cctrl_reply(gateway *g, cctrl *cc, const char *msg) {
    size_t len = strlen(msg);
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = write(cc->fd, msg + sent, len - sent);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        break;
    }
    (void)ntc_poller_del(g->p, cc->fd);
    close(cc->fd);
    free(cc);
}

/* Execute a control command (token already verified). Writes a reply line
 * (OK.../ERR...) to out. Callable from the control socket AND the in-core MCP. */
static void exec_control_command(gateway *g, char *cmdline, char *out, size_t cap) {
    char *save = NULL;
    char *cmd = strtok_r(cmdline, " ", &save);
    if (!cmd) { snprintf(out, cap, "ERR empty command\n"); return; }

    if (strcmp(cmd, "ping") == 0) {
        snprintf(out, cap, "OK pong\n");
    } else if (strcmp(cmd, "status") == 0) {
        long up = (now_ms() - g->m.start_ms) / 1000;
        snprintf(out, cap,
            "OK {\"app\":\"%s\",\"uptime_s\":%ld,\"services\":%zu,\"routes\":%zu,"
            "\"backend\":\"%s\",\"requests\":%llu,\"status_2xx\":%llu,\"status_4xx\":%llu,"
            "\"status_5xx\":%llu,\"forwarded\":%llu,\"builtin\":%llu,\"inflight_cap\":%u}\n",
            g->app_name, up, g->nservices, ntc_router_count(g->router), ntc_poller_backend(),
            (unsigned long long)g->m.requests_total, (unsigned long long)g->m.status_2xx,
            (unsigned long long)g->m.status_4xx, (unsigned long long)g->m.status_5xx,
            (unsigned long long)g->m.forwarded, (unsigned long long)g->m.builtin, NTC_MAX_INFLIGHT);
    } else if (strcmp(cmd, "service-add") == 0) {
        char *name = strtok_r(NULL, " ", &save);
        char *bin = strtok_r(NULL, " ", &save);
        if (!name || !bin) { snprintf(out, cap, "ERR usage: service-add <name> <bin>\n"); return; }
        if (ntc_registry_add_service(g->reg, name, bin) != NTC_OK) { snprintf(out, cap, "ERR registry write failed\n"); return; }
        if (!service_add_live(g, name, bin)) { snprintf(out, cap, "ERR too many services\n"); return; }
        snprintf(out, cap, "OK service added\n");
    } else if (strcmp(cmd, "route-add") == 0) {
        char *method = strtok_r(NULL, " ", &save);
        char *pattern = strtok_r(NULL, " ", &save);
        char *svcname = strtok_r(NULL, " ", &save);
        if (!method || !pattern || !svcname) { snprintf(out, cap, "ERR usage: route-add <METHOD> <pattern> <service>\n"); return; }
        if (ntc_registry_add_route(g->reg, method, pattern, svcname) != NTC_OK) { snprintf(out, cap, "ERR unknown service\n"); return; }
        service *svc = find_service(g, svcname);
        if (!svc) { snprintf(out, cap, "ERR service not loaded\n"); return; }
        if (ntc_router_add(g->router, method, pattern, forward_marker, svc) != NTC_OK) { snprintf(out, cap, "ERR route register failed\n"); return; }
        snprintf(out, cap, "OK route added\n");
    } else if (strcmp(cmd, "service-rm") == 0) {
        char *name = strtok_r(NULL, " ", &save);
        if (!name) { snprintf(out, cap, "ERR usage: service-rm <name>\n"); return; }
        ntc_err e = ntc_registry_remove_service(g->reg, name);
        service *svc = find_service(g, name);
        if (svc) {
            svc->disabled = true;
            if (svc->conn) { ctrl *ct = svc->conn; svc->conn = NULL;
                (void)ntc_poller_del(g->p, ct->fd); kill(ct->pid, SIGTERM); close(ct->fd);
                waitpid(ct->pid, NULL, WNOHANG); free(ct->rbuf); free(ct->wbuf); free(ct); }
        }
        snprintf(out, cap, "%s", e == NTC_OK ? "OK service removed\n" : "ERR not found\n");
    } else if (strcmp(cmd, "service-list") == 0) {
        ntc_service_row rows[64]; size_t n = 0;
        (void)ntc_registry_list_services(g->reg, rows, 64, &n);
        size_t off = (size_t)snprintf(out, cap, "OK [");
        for (size_t i = 0; i < n && off < cap - 128; i++)
            off += (size_t)snprintf(out + off, cap - off, "%s{\"name\":\"%s\",\"bin\":\"%s\"}",
                                    i ? "," : "", rows[i].name, rows[i].bin);
        snprintf(out + off, cap - off, "]\n");
    } else if (strcmp(cmd, "route-list") == 0) {
        ntc_route_row rows[128]; size_t n = 0;
        (void)ntc_registry_list_routes(g->reg, rows, 128, &n);
        size_t off = (size_t)snprintf(out, cap, "OK [");
        for (size_t i = 0; i < n && off < cap - 160; i++)
            off += (size_t)snprintf(out + off, cap - off,
                                    "%s{\"method\":\"%s\",\"pattern\":\"%s\",\"service\":\"%s\"}",
                                    i ? "," : "", rows[i].method, rows[i].pattern, rows[i].service);
        snprintf(out + off, cap - off, "]\n");
    } else if (strcmp(cmd, "config-set") == 0) {
        char *key = strtok_r(NULL, " ", &save);
        char *val = save;
        while (val && *val == ' ') val++;
        if (!key || !val || !*val) { snprintf(out, cap, "ERR usage: config-set <key> <value>\n"); return; }
        if (ntc_registry_set_config(g->reg, key, val) != NTC_OK) { snprintf(out, cap, "ERR write failed\n"); return; }
        if (strcmp(key, "app.name") == 0) snprintf(g->app_name, sizeof g->app_name, "%s", val);
        snprintf(out, cap, "OK config set\n");
    } else if (strcmp(cmd, "config-get") == 0) {
        char *key = strtok_r(NULL, " ", &save);
        if (!key) { snprintf(out, cap, "ERR usage: config-get <key>\n"); return; }
        char val[512]; bool found = false;
        (void)ntc_registry_get_config(g->reg, key, val, sizeof val, &found);
        if (found) snprintf(out, cap, "OK %s\n", val); else snprintf(out, cap, "ERR not found\n");
    } else if (strcmp(cmd, "stop") == 0) {
        g_stop = 1;
        snprintf(out, cap, "OK stopping\n");
    } else {
        snprintf(out, cap, "ERR unknown command\n");
    }
}

static void process_control(gateway *g, cctrl *cc) {
    char *nl = memchr(cc->buf, '\n', cc->len);
    if (nl) *nl = '\0';
    else cc->buf[cc->len < sizeof cc->buf ? cc->len : sizeof cc->buf - 1] = '\0';

    char *sp = strchr(cc->buf, ' ');
    char *token = cc->buf;
    char *rest = "";
    if (sp) { *sp = '\0'; rest = sp + 1; }
    if (strcmp(token, g->token) != 0) { cctrl_reply(g, cc, "ERR unauthorized\n"); return; }

    char out[8192];
    exec_control_command(g, rest, out, sizeof out);
    cctrl_reply(g, cc, out);
}

static void on_control_readable(gateway *g, cctrl *cc) {
    for (;;) {
        if (cc->len >= sizeof cc->buf - 1) { process_control(g, cc); return; }
        ssize_t n = recv(cc->fd, cc->buf + cc->len, sizeof cc->buf - 1 - cc->len, 0);
        if (n > 0) {
            cc->len += (size_t)n;
            if (memchr(cc->buf, '\n', cc->len)) { process_control(g, cc); return; }
            continue;
        }
        if (n == 0) { (void)ntc_poller_del(g->p, cc->fd); close(cc->fd); free(cc); return; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        (void)ntc_poller_del(g->p, cc->fd); close(cc->fd); free(cc);
        return;
    }
}

static void accept_control(gateway *g) {
    for (;;) {
        int cfd = accept(g->control_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            return; /* EAGAIN or other: done */
        }
        if (set_nonblocking(cfd) < 0) { close(cfd); continue; }
        cctrl *cc = calloc(1, sizeof *cc);
        if (!cc) { close(cfd); continue; }
        cc->kind = KIND_CONTROL;
        cc->fd = cfd;
        cc->gw = g;
        if (ntc_poller_add(g->p, cfd, NTC_POLL_READ, cc) != NTC_OK) { close(cfd); free(cc); }
    }
}

ntc_err ntc_server_run(uint16_t port, uint16_t admin_port, uint16_t tls_port,
                       const ntc_dev_opts *dev) {
    gateway g;
    memset(&g, 0, sizeof g);
    gw_slots_init(&g);
    g.tls_fd = -1;
    g.m.start_ms = now_ms();
    if (dev && dev->watch) {
        g.dev_watch = true;
        g.dev_build = dev->build_cmd;
        for (size_t i = 0; i < dev->npaths && g.dev_npaths < NTC_DEV_MAX_WATCH; i++)
            g.dev_paths[g.dev_npaths++] = dev->paths[i];
    }

    if (ntc_router_create(&g.router) != NTC_OK) return NTC_ERR_OOM;
    if (ntc_builtin_register(g.router) != NTC_OK) { ntc_router_destroy(g.router); return NTC_ERR_INTERNAL; }

    const char *dbpath = getenv("NTC_DB");
    if (!dbpath) dbpath = "ntc.db";
    if (ntc_registry_open(&g.reg, dbpath) != NTC_OK) {
        NTC_ERROR("cannot open registry '%s'", dbpath);
        ntc_router_destroy(g.router);
        return NTC_ERR_IO;
    }
    g.control_fd = -1;
    g.admin_fd = -1;
    g.services = calloc(NTC_MAX_SERVICES, sizeof(service));
    if (!g.services) { ntc_registry_close(g.reg); ntc_router_destroy(g.router); return NTC_ERR_OOM; }
    load_token(&g);
    {
        char an[128]; bool found = false;
        if (ntc_registry_get_config(g.reg, "app.name", an, sizeof an, &found) == NTC_OK && found)
            snprintf(g.app_name, sizeof g.app_name, "%s", an);
        else {
            const char *e = getenv("NTC_APP_NAME");
            snprintf(g.app_name, sizeof g.app_name, "%s", e ? e : "naitron-c app");
        }
        char sd[256]; bool sf = false;
        if (ntc_registry_get_config(g.reg, "static.dir", sd, sizeof sd, &sf) == NTC_OK && sf)
            snprintf(g.static_dir, sizeof g.static_dir, "%s", sd);
        const char *se = getenv("NTC_STATIC_DIR");
        if (se) snprintf(g.static_dir, sizeof g.static_dir, "%s", se);
    }
    {
        ntc_mw_config mcfg;
        memset(&mcfg, 0, sizeof mcfg);
        mcfg.request_id = true;
        mcfg.access_log = true;
        char v[256]; bool f = false;
        if (ntc_registry_get_config(g.reg, "cors.origin", v, sizeof v, &f) == NTC_OK && f)
            snprintf(mcfg.cors_origin, sizeof mcfg.cors_origin, "%s", v);
        if (ntc_registry_get_config(g.reg, "ratelimit.per_sec", v, sizeof v, &f) == NTC_OK && f)
            mcfg.rate_per_sec = atoi(v);
        if (ntc_registry_get_config(g.reg, "ratelimit.burst", v, sizeof v, &f) == NTC_OK && f)
            mcfg.rate_burst = atoi(v);
        if (ntc_registry_get_config(g.reg, "accesslog", v, sizeof v, &f) == NTC_OK && f)
            mcfg.access_log = atoi(v) != 0;
        if (ntc_registry_get_config(g.reg, "auth.mode", v, sizeof v, &f) == NTC_OK && f)
            snprintf(mcfg.auth_mode, sizeof mcfg.auth_mode, "%s", v);
        if (ntc_registry_get_config(g.reg, "auth.secret", v, sizeof v, &f) == NTC_OK && f)
            snprintf(mcfg.auth_secret, sizeof mcfg.auth_secret, "%s", v);
        if (ntc_registry_get_config(g.reg, "auth.protect", v, sizeof v, &f) == NTC_OK && f)
            snprintf(mcfg.auth_protect, sizeof mcfg.auth_protect, "%s", v);
        if (ntc_registry_get_config(g.reg, "auth.jwks_file", v, sizeof v, &f) == NTC_OK && f)
            snprintf(mcfg.auth_jwks_file, sizeof mcfg.auth_jwks_file, "%s", v);
        if (ntc_registry_get_config(g.reg, "auth.jwks_url", v, sizeof v, &f) == NTC_OK && f)
            snprintf(mcfg.auth_jwks_url, sizeof mcfg.auth_jwks_url, "%s", v);
        if (ntc_registry_get_config(g.reg, "auth.jwks_ca", v, sizeof v, &f) == NTC_OK && f)
            snprintf(mcfg.auth_jwks_ca, sizeof mcfg.auth_jwks_ca, "%s", v);
        /* env overrides (handy for ops/tests) */
        const char *e;
        if ((e = getenv("NTC_CORS_ORIGIN"))) snprintf(mcfg.cors_origin, sizeof mcfg.cors_origin, "%s", e);
        if ((e = getenv("NTC_RATELIMIT_PER_SEC"))) mcfg.rate_per_sec = atoi(e);
        if ((e = getenv("NTC_RATELIMIT_BURST"))) mcfg.rate_burst = atoi(e);
        if ((e = getenv("NTC_AUTH_MODE"))) snprintf(mcfg.auth_mode, sizeof mcfg.auth_mode, "%s", e);
        if ((e = getenv("NTC_AUTH_SECRET"))) snprintf(mcfg.auth_secret, sizeof mcfg.auth_secret, "%s", e);
        if ((e = getenv("NTC_AUTH_PROTECT"))) snprintf(mcfg.auth_protect, sizeof mcfg.auth_protect, "%s", e);
        if ((e = getenv("NTC_AUTH_JWKS_FILE"))) snprintf(mcfg.auth_jwks_file, sizeof mcfg.auth_jwks_file, "%s", e);
        if ((e = getenv("NTC_AUTH_JWKS_URL"))) snprintf(mcfg.auth_jwks_url, sizeof mcfg.auth_jwks_url, "%s", e);
        if ((e = getenv("NTC_AUTH_JWKS_CA"))) snprintf(mcfg.auth_jwks_ca, sizeof mcfg.auth_jwks_ca, "%s", e);
        g.mw = ntc_mw_new(&mcfg);
    }

    /* OAuth2 login (M12): enabled when oauth.token_url is configured. */
    {
        struct { const char *key; const char *env; char *dst; size_t cap; } oc[] = {
            { "oauth.authorize_url", "NTC_OAUTH_AUTHORIZE_URL", g.oauth_authorize_url, sizeof g.oauth_authorize_url },
            { "oauth.token_url",     "NTC_OAUTH_TOKEN_URL",     g.oauth_token_url,     sizeof g.oauth_token_url },
            { "oauth.client_id",     "NTC_OAUTH_CLIENT_ID",     g.oauth_client_id,     sizeof g.oauth_client_id },
            { "oauth.client_secret", "NTC_OAUTH_CLIENT_SECRET", g.oauth_client_secret, sizeof g.oauth_client_secret },
            { "oauth.redirect_uri",  "NTC_OAUTH_REDIRECT_URI",  g.oauth_redirect_uri,  sizeof g.oauth_redirect_uri },
            { "oauth.scopes",        "NTC_OAUTH_SCOPES",        g.oauth_scopes,        sizeof g.oauth_scopes },
            { "oauth.success",       "NTC_OAUTH_SUCCESS",       g.oauth_success,       sizeof g.oauth_success },
        };
        char v[256]; bool f = false;
        for (size_t i = 0; i < sizeof oc / sizeof oc[0]; i++) {
            if (ntc_registry_get_config(g.reg, oc[i].key, v, sizeof v, &f) == NTC_OK && f)
                snprintf(oc[i].dst, oc[i].cap, "%s", v);
            const char *e = getenv(oc[i].env);
            if (e) snprintf(oc[i].dst, oc[i].cap, "%s", e);
        }
        if (g.oauth_token_url[0] && g.oauth_authorize_url[0] && g.oauth_client_id[0]) {
            g.sessions = ntc_kv_new(4096);
            g.oauth_pending = ntc_kv_new(1024);
            char ca[256] = ""; bool cf = false;
            if (ntc_registry_get_config(g.reg, "oauth.ca", ca, sizeof ca, &cf) == NTC_OK && cf) {}
            const char *cae = getenv("NTC_OAUTH_CA"); if (cae) snprintf(ca, sizeof ca, "%s", cae);
            g.oauth_ca = ca[0] ? ntc_ca_load_pem(ca) : ntc_ca_default();
            g.oauth_enabled = g.sessions && g.oauth_pending;
            if (g.oauth_enabled)
                NTC_SUCCESS("oauth: login enabled (/auth/login -> %s)", g.oauth_authorize_url);
            if (!g.oauth_ca)
                NTC_WARN("oauth: no CA roots for the token endpoint (set oauth.ca); exchange will fail closed");
        }
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

    const char *csock = ntc_control_sock_path();
    g.control_fd = make_control_socket(csock);
    if (g.control_fd >= 0) {
        if (ntc_poller_add(g.p, g.control_fd, NTC_POLL_READ, NULL) != NTC_OK) {
            close(g.control_fd); unlink(csock); g.control_fd = -1;
        }
    } else {
        NTC_WARN("control socket '%s' unavailable; CLI control disabled", csock);
    }

    if (admin_port > 0) {
        g.admin_fd = make_admin_socket(admin_port);
        if (g.admin_fd >= 0) {
            if (ntc_poller_add(g.p, g.admin_fd, NTC_POLL_READ, NULL) != NTC_OK) {
                close(g.admin_fd); g.admin_fd = -1;
            } else {
                NTC_SUCCESS("dashboard on http://127.0.0.1:%u  (read-only)", (unsigned)admin_port);
            }
        } else {
            NTC_WARN("admin port %u unavailable; dashboard disabled", (unsigned)admin_port);
        }
    }

    {
        /* HTTPS listener. Port: CLI --tls wins, else tls.port / NTC_TLS_PORT.
         * Cert + key (both PEM): tls.cert/tls.key or NTC_TLS_CERT/NTC_TLS_KEY. */
        uint16_t tport = tls_port;
        char vv[256]; bool ff = false;
        if (!tport && ntc_registry_get_config(g.reg, "tls.port", vv, sizeof vv, &ff) == NTC_OK && ff)
            tport = (uint16_t)atoi(vv);
        const char *tpe = getenv("NTC_TLS_PORT"); if (tpe) tport = (uint16_t)atoi(tpe);

        char cert[256] = "", key[256] = "";
        if (ntc_registry_get_config(g.reg, "tls.cert", vv, sizeof vv, &ff) == NTC_OK && ff)
            snprintf(cert, sizeof cert, "%s", vv);
        if (ntc_registry_get_config(g.reg, "tls.key", vv, sizeof vv, &ff) == NTC_OK && ff)
            snprintf(key, sizeof key, "%s", vv);
        const char *ce = getenv("NTC_TLS_CERT"); if (ce) snprintf(cert, sizeof cert, "%s", ce);
        const char *ke = getenv("NTC_TLS_KEY");  if (ke) snprintf(key, sizeof key, "%s", ke);

        if (tport > 0) {
            if (!cert[0] || !key[0]) {
                NTC_WARN("tls: port %u set but tls.cert/tls.key missing; HTTPS disabled", (unsigned)tport);
            } else if (!(g.tls_conf = ntc_tls_conf_new(cert, key))) {
                NTC_WARN("tls: failed to load cert/key; HTTPS disabled");
            } else if ((g.tls_fd = make_tls_socket(tport)) < 0 ||
                       ntc_poller_add(g.p, g.tls_fd, NTC_POLL_READ, NULL) != NTC_OK) {
                if (g.tls_fd >= 0) { close(g.tls_fd); g.tls_fd = -1; }
                ntc_tls_conf_free(g.tls_conf); g.tls_conf = NULL;
                NTC_WARN("tls: port %u unavailable; HTTPS disabled", (unsigned)tport);
            } else {
                NTC_SUCCESS("naitron-c TLS on https://0.0.0.0:%u", (unsigned)tport);
            }
        }
    }

    if (load_registry(&g) != NTC_OK) NTC_WARN("registry load incomplete");
    for (size_t i = 0; i < g.nservices; i++) (void)spawn_service(&g, &g.services[i]);

    NTC_SUCCESS("naitron-c listening on http://0.0.0.0:%u  (%s, %zu routes, %zu services, control %s)",
                (unsigned)port, ntc_poller_backend(), ntc_router_count(g.router), g.nservices,
                g.control_fd >= 0 ? csock : "off");
    if (g.dev_watch) {
        NTC_INFO("dev: hot-reload on (poll %dms); watching %zu source path(s)%s%s",
                 NTC_DEV_POLL_MS, g.dev_npaths, g.dev_build ? ", build: " : "",
                 g.dev_build ? g.dev_build : "");
    }

    ntc_poll_event evs[NTC_MAX_EVENTS];
    while (!g_stop) {
        int n = ntc_poller_wait(g.p, evs, NTC_MAX_EVENTS, poll_timeout(&g));
        if (n < 0) {
            if (errno == EINTR) { dev_tick(&g); supervise(&g); continue; }
            NTC_ERROR("poller_wait(): %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].fd == listen_fd) { accept_conns(&g, listen_fd, false, false); continue; }
            if (evs[i].fd == g.admin_fd) { accept_conns(&g, g.admin_fd, true, false); continue; }
            if (g.tls_fd >= 0 && evs[i].fd == g.tls_fd) { accept_conns(&g, g.tls_fd, false, true); continue; }
            if (evs[i].fd == g.control_fd) { accept_control(&g); continue; }
            int kind = *(int *)evs[i].udata;
            if (kind == KIND_CONTROL) {
                if (evs[i].events & NTC_POLL_READ) on_control_readable(&g, evs[i].udata);
                continue;
            }
            if (kind == KIND_CTRL) {
                ctrl *ct = evs[i].udata;
                if ((evs[i].events & NTC_POLL_READ) && on_ctrl_readable(&g, ct) < 0) continue;
                if (evs[i].events & NTC_POLL_WRITE) on_ctrl_writable(&g, ct);
                continue;
            }
            conn *c = evs[i].udata;
            if (c->tls) { on_tls_event(&g, c); continue; }
            if (c->state == CS_READ) {
                if ((evs[i].events & NTC_POLL_READ) && on_readable(&g, c) < 0) continue;
            } else if (c->state == CS_WAIT) {
                if (evs[i].events & NTC_POLL_READ) on_wait_readable(&g, c);
            } else if (c->state == CS_STREAM) {
                if ((evs[i].events & NTC_POLL_WRITE) && on_writable(&g, c) < 0) continue;
                if (evs[i].events & NTC_POLL_READ) on_wait_readable(&g, c); /* detect client EOF */
            } else if (c->state == CS_WS) {
                if ((evs[i].events & NTC_POLL_WRITE) && on_writable(&g, c) < 0) continue;
                if ((evs[i].events & NTC_POLL_READ) && on_ws_readable(&g, c) < 0) continue;
            } else {
                if (evs[i].events & NTC_POLL_WRITE) (void)on_writable(&g, c);
            }
        }
        dev_tick(&g);
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
    if (g.admin_fd >= 0) close(g.admin_fd);
    if (g.tls_fd >= 0) close(g.tls_fd);
    if (g.tls_conf) ntc_tls_conf_free(g.tls_conf);
    if (g.control_fd >= 0) { close(g.control_fd); unlink(ntc_control_sock_path()); }
    ntc_mw_free(g.mw);
    ntc_kv_free(g.sessions); ntc_kv_free(g.oauth_pending); ntc_ca_free(g.oauth_ca);
    ntc_registry_close(g.reg);
    ntc_router_destroy(g.router);
    return NTC_OK;

fail_pre_poll:
    free(g.services);
    if (g.tls_conf) ntc_tls_conf_free(g.tls_conf);
    ntc_mw_free(g.mw);
    ntc_kv_free(g.sessions); ntc_kv_free(g.oauth_pending); ntc_ca_free(g.oauth_ca);
    ntc_registry_close(g.reg);
    ntc_router_destroy(g.router);
    return NTC_ERR_IO;
}

#ifdef UNIT_TEST
#include "ntc/test.h"
#include <sys/socket.h>

TEST(dev, mtime_helpers) {
    const char *dir = "/tmp/ntc_dev_mt_test";
    mkdir(dir, 0755);
    char fa[256], fb[256];
    snprintf(fa, sizeof fa, "%s/a.c", dir);
    snprintf(fb, sizeof fb, "%s/b.c", dir);
    FILE *f = fopen(fa, "w"); ASSERT_NOT_NULL(f); fputs("a", f); fclose(f);
    f = fopen(fb, "w"); ASSERT_NOT_NULL(f); fputs("b", f); fclose(f);

    /* set explicit mtimes so the test is deterministic (no sleeps) */
    struct timespec ta[2] = { { 1000, 0 }, { 1000, 0 } };
    struct timespec tb[2] = { { 2000, 0 }, { 2000, 0 } };
    ASSERT_EQ_INT(0, utimensat(AT_FDCWD, fa, ta, 0));
    ASSERT_EQ_INT(0, utimensat(AT_FDCWD, fb, tb, 0));

    ASSERT_TRUE(path_mtime_ns(fa) == 1000000000000LL);
    ASSERT_TRUE(path_mtime_ns(fb) == 2000000000000LL);
    ASSERT_TRUE(tree_max_mtime(dir) == 2000000000000LL); /* max over the tree */

    /* bump a.c to be the newest -> tree max follows it */
    struct timespec tc[2] = { { 3000, 0 }, { 3000, 0 } };
    ASSERT_EQ_INT(0, utimensat(AT_FDCWD, fa, tc, 0));
    ASSERT_TRUE(tree_max_mtime(dir) == 3000000000000LL);

    ASSERT_TRUE(path_mtime_ns("/tmp/ntc_dev_mt_test/nope") == -1);

    unlink(fa); unlink(fb); rmdir(dir);
}

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
