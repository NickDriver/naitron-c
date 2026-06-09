#define _GNU_SOURCE /* MSG_NOSIGNAL on Linux; harmless on macOS */
#include "ntc/server.h"

#include "ntc/arena.h"
#include "ntc/http.h"
#include "ntc/log.h"
#include "ntc/slice.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static volatile sig_atomic_t g_stop = 0;

static void on_stop(int sig) {
    (void)sig;
    g_stop = 1;
}

static ntc_err send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return NTC_ERR_IO;
        }
        sent += (size_t)n;
    }
    return NTC_OK;
}

static void handle_conn(int fd) {
    /* Drain what the client sent; real parsing/routing lands in P2/P3. */
    char scratch[2048];
    ssize_t r = recv(fd, scratch, sizeof scratch, 0);
    (void)r;

    ntc_arena a;
    if (ntc_arena_init(&a, 4096) != NTC_OK) return; /* drop on OOM */

    ntc_slice body = NTC_SLICE_LIT(
        "{\"service\":\"naitron-c\",\"status\":\"ok\","
        "\"message\":\"P0 gateway alive\"}");

    ntc_slice resp;
    if (ntc_http_format_response(&a, 200, "OK",
            NTC_SLICE_LIT("application/json"), body, &resp) == NTC_OK) {
        if (send_all(fd, resp.ptr, resp.len) != NTC_OK)
            NTC_WARN("send failed: %s", strerror(errno));
    }

    ntc_arena_destroy(&a);
}

ntc_err ntc_server_run(uint16_t port, uint16_t admin_port) {
    (void)admin_port; /* read-only dashboard: P8 */

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        NTC_ERROR("socket(): %s", strerror(errno));
        return NTC_ERR_IO;
    }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(listen_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif

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
    if (listen(listen_fd, 128) < 0) {
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

    NTC_SUCCESS("naitron-c listening on http://0.0.0.0:%u  (Ctrl-C to stop)",
                (unsigned)port);

    while (!g_stop) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue; /* signal (incl. stop) interrupted us */
            NTC_WARN("accept(): %s", strerror(errno));
            continue;
        }
#ifdef SO_NOSIGPIPE
        int yes = 1;
        setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof yes);
#endif
        handle_conn(cfd);
        close(cfd);
    }

    NTC_INFO("shutting down");
    close(listen_fd);
    return NTC_OK;
}
