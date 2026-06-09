#define _GNU_SOURCE /* MSG_NOSIGNAL on Linux; harmless on macOS */
#include "ntc/server.h"

#include "ntc/arena.h"
#include "ntc/http.h"
#include "ntc/log.h"
#include "ntc/poller.h"
#include "ntc/slice.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define NTC_MAX_EVENTS 256
#define NTC_CONN_RBUF  (16 * 1024)

static volatile sig_atomic_t g_stop = 0;
static void on_stop(int sig) { (void)sig; g_stop = 1; }

/* ---- per-connection state machine -------------------------------------- */

typedef enum { CS_READ, CS_WRITE } conn_state;

typedef struct conn {
    int fd;
    conn_state state;
    ntc_arena arena;     /* holds the response bytes */
    size_t rlen;         /* bytes buffered in rbuf    */
    const char *wbuf;    /* response, points into arena */
    size_t wlen, wsent;
    char rbuf[NTC_CONN_RBUF];
} conn;

static int set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static const char *find_eoh(const char *b, size_t n) {
    for (size_t i = 0; i + 4 <= n; i++)
        if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n')
            return b + i;
    return NULL;
}

static conn *conn_new(int fd) {
    conn *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->fd = fd;
    c->state = CS_READ;
    if (ntc_arena_init(&c->arena, 4096) != NTC_OK) { free(c); return NULL; }
    return c;
}

static void conn_close(ntc_poller *p, conn *c) {
    (void)ntc_poller_del(p, c->fd);
    close(c->fd);
    ntc_arena_destroy(&c->arena);
    free(c);
}

static int conn_build_response(conn *c) {
    ntc_slice body = NTC_SLICE_LIT(
        "{\"service\":\"naitron-c\",\"status\":\"ok\","
        "\"message\":\"P1 event loop\"}");
    ntc_slice resp;
    if (ntc_http_format_response(&c->arena, 200, "OK",
            NTC_SLICE_LIT("application/json"), body, &resp) != NTC_OK)
        return -1;
    c->wbuf = resp.ptr;
    c->wlen = resp.len;
    c->wsent = 0;
    c->state = CS_WRITE;
    return 0;
}

/* returns 0 if the connection is still alive, -1 if it was closed/freed */
static int on_writable(ntc_poller *p, conn *c) {
    while (c->wsent < c->wlen) {
        ssize_t n = send(c->fd, c->wbuf + c->wsent, c->wlen - c->wsent, MSG_NOSIGNAL);
        if (n > 0) { c->wsent += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0; /* wait */
        conn_close(p, c);
        return -1;
    }
    conn_close(p, c); /* response sent; Connection: close */
    return -1;
}

static int on_readable(ntc_poller *p, conn *c) {
    for (;;) {
        if (c->rlen >= sizeof c->rbuf) break; /* headers too big: just answer */
        ssize_t n = recv(c->fd, c->rbuf + c->rlen, sizeof c->rbuf - c->rlen, 0);
        if (n > 0) {
            c->rlen += (size_t)n;
            if (find_eoh(c->rbuf, c->rlen)) break; /* end of headers */
            continue;
        }
        if (n == 0) {                       /* peer closed */
            if (c->rlen == 0) { conn_close(p, c); return -1; }
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; /* wait for more */
        conn_close(p, c);
        return -1;
    }

    if (conn_build_response(c) != 0) { conn_close(p, c); return -1; }
    if (ntc_poller_mod(p, c->fd, NTC_POLL_WRITE, c) != NTC_OK) {
        conn_close(p, c);
        return -1;
    }
    return on_writable(p, c); /* opportunistic first write */
}

static void accept_all(ntc_poller *p, int listen_fd) {
    for (;;) {
        int cfd = accept(listen_fd, NULL, NULL);
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
        conn *c = conn_new(cfd);
        if (!c) { close(cfd); continue; }
        if (ntc_poller_add(p, cfd, NTC_POLL_READ, c) != NTC_OK) {
            ntc_arena_destroy(&c->arena);
            close(cfd);
            free(c);
        }
    }
}

ntc_err ntc_server_run(uint16_t port, uint16_t admin_port) {
    (void)admin_port; /* read-only dashboard: P8 */

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { NTC_ERROR("socket(): %s", strerror(errno)); return NTC_ERR_IO; }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(listen_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    if (set_nonblocking(listen_fd) < 0) {
        NTC_ERROR("fcntl(O_NONBLOCK): %s", strerror(errno));
        close(listen_fd);
        return NTC_ERR_IO;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        NTC_ERROR("bind(:%u): %s", (unsigned)port, strerror(errno));
        close(listen_fd);
        return NTC_ERR_IO;
    }
    if (listen(listen_fd, 256) < 0) {
        NTC_ERROR("listen(): %s", strerror(errno));
        close(listen_fd);
        return NTC_ERR_IO;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_stop;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    ntc_poller *p = NULL;
    if (ntc_poller_create(&p) != NTC_OK) {
        NTC_ERROR("poller_create failed");
        close(listen_fd);
        return NTC_ERR_IO;
    }
    if (ntc_poller_add(p, listen_fd, NTC_POLL_READ, NULL) != NTC_OK) {
        ntc_poller_destroy(p);
        close(listen_fd);
        return NTC_ERR_IO;
    }

    NTC_SUCCESS("naitron-c listening on http://0.0.0.0:%u  (%s, Ctrl-C to stop)",
                (unsigned)port, ntc_poller_backend());

    ntc_poll_event evs[NTC_MAX_EVENTS];
    while (!g_stop) {
        int n = ntc_poller_wait(p, evs, NTC_MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            NTC_ERROR("poller_wait(): %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].fd == listen_fd) { accept_all(p, listen_fd); continue; }
            conn *c = evs[i].udata;
            if (!c) continue;
            if ((evs[i].events & NTC_POLL_READ) && on_readable(p, c) < 0) continue;
            if (evs[i].events & NTC_POLL_WRITE) (void)on_writable(p, c);
        }
    }

    NTC_INFO("shutting down");
    ntc_poller_destroy(p);
    close(listen_fd);
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
    ASSERT_EQ_INT(0, ntc_poller_wait(p, evs, 4, 50)); /* nothing ready -> timeout */

    ASSERT_EQ_INT(1, (int)write(sv[1], "x", 1));
    int n = ntc_poller_wait(p, evs, 4, 1000);
    ASSERT_EQ_INT(1, n);
    ASSERT_EQ_INT(sv[0], evs[0].fd);
    ASSERT_TRUE((evs[0].events & NTC_POLL_READ) != 0);
    ASSERT_TRUE(evs[0].udata == &marker);

    ASSERT_EQ_INT(NTC_OK, ntc_poller_del(p, sv[0]));
    close(sv[0]);
    close(sv[1]);
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
    close(sv[0]);
    close(sv[1]);
    ntc_poller_destroy(p);
}

TEST(poller, mod_switches_interest) {
    ntc_poller *p = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_poller_create(&p));
    int sv[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    /* start watching READ (nothing to read) */
    ASSERT_EQ_INT(NTC_OK, ntc_poller_add(p, sv[0], NTC_POLL_READ, NULL));
    ntc_poll_event evs[4];
    ASSERT_EQ_INT(0, ntc_poller_wait(p, evs, 4, 50));
    /* switch to WRITE (socket is writable) -> should fire */
    ASSERT_EQ_INT(NTC_OK, ntc_poller_mod(p, sv[0], NTC_POLL_WRITE, NULL));
    int n = ntc_poller_wait(p, evs, 4, 1000);
    ASSERT_TRUE(n >= 1);
    ASSERT_TRUE((evs[0].events & NTC_POLL_WRITE) != 0);

    ASSERT_EQ_INT(NTC_OK, ntc_poller_del(p, sv[0]));
    close(sv[0]);
    close(sv[1]);
    ntc_poller_destroy(p);
}

TEST(poller, backend_name_known) {
    const char *b = ntc_poller_backend();
    ASSERT_NOT_NULL(b);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(b), "kqueue") ||
                ntc_slice_eq_cstr(ntc_slice_cstr(b), "epoll"));
}
#endif /* UNIT_TEST */
