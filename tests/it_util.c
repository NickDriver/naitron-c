#define _GNU_SOURCE
#include "it_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

pid_t it_spawn(const char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* quiet the child's stdout/stderr so test output stays clean (debug:
         * set NTC_IT_SPAWN_LOG to capture every spawned gateway's output) */
        const char *dbg = getenv("NTC_IT_SPAWN_LOG");
        int nul = open(dbg && dbg[0] ? dbg : "/dev/null", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (nul >= 0) { dup2(nul, 1); dup2(nul, 2); close(nul); }
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    return pid;
}

static int connect_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

bool it_wait_port(int port, int timeout_ms) {
    struct timespec slp = { 0, 20 * 1000 * 1000 }; /* 20ms */
    for (int waited = 0; waited <= timeout_ms; waited += 20) {
        int fd = connect_port(port);
        if (fd >= 0) { close(fd); return true; }
        nanosleep(&slp, NULL);
    }
    return false;
}

int it_send(int port, const char *raw, char *resp, size_t cap) {
    int fd = connect_port(port);
    if (fd < 0) return -1;
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    size_t len = strlen(raw), sent = 0;
    while (sent < len) {
        ssize_t w = write(fd, raw + sent, len - sent);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        close(fd); return -1;
    }

    size_t got = 0;
    while (got + 1 < cap) {
        ssize_t r = read(fd, resp + got, cap - 1 - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    resp[got] = '\0';
    close(fd);
    return (int)got;
}

int it_get(int port, const char *path, char *resp, size_t cap) {
    char req[1024];
    snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", path);
    return it_send(port, req, resp, cap);
}

int it_status(const char *resp) {
    int code = 0;
    if (sscanf(resp, "HTTP/1.%*d %d", &code) == 1) return code;
    return -1;
}

void it_iso(const char *tag) {
    char p[256];
    const char *vars[] = { "NTC_DB", "NTC_CONTROL_SOCK", "NTC_TOKEN_FILE",
                           "NTC_PID_FILE", "NTC_LOG_FILE" };
    const char *ext[] = { "db", "sock", "token", "pid", "log" };
    for (int i = 0; i < 5; i++) {
        snprintf(p, sizeof p, "/tmp/ntc_it_%s.%s", tag, ext[i]);
        setenv(vars[i], p, 1);
        unlink(p);
    }
}

void it_stop(pid_t pid) {
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    for (int i = 0; i < 100; i++) { /* up to ~2s for graceful exit */
        if (waitpid(pid, NULL, WNOHANG) == pid) return;
        struct timespec slp = { 0, 20 * 1000 * 1000 };
        nanosleep(&slp, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}
