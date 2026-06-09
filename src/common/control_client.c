#define _GNU_SOURCE
#include "ntc/control.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

const char *ntc_control_sock_path(void) {
    const char *s = getenv("NTC_CONTROL_SOCK");
    return s ? s : NTC_CONTROL_SOCK_DEFAULT;
}

ntc_err ntc_control_read_token(char *out, size_t cap) {
    if (!out || cap == 0) return NTC_ERR_INVALID;
    out[0] = '\0';
    const char *env = getenv("NTC_TOKEN");
    if (env && env[0]) {
        snprintf(out, cap, "%s", env);
        return NTC_OK;
    }
    const char *tf = getenv("NTC_TOKEN_FILE");
    if (!tf) tf = NTC_CONTROL_TOKEN_DEFAULT;
    FILE *f = fopen(tf, "r");
    if (!f) return NTC_ERR_NOT_FOUND;
    char *p = fgets(out, (int)cap, f);
    fclose(f);
    if (!p) return NTC_ERR_NOT_FOUND;
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    return NTC_OK;
}

ntc_err ntc_control_call(const char *sock_path, const char *token,
                         const char *command, char *out, size_t out_cap) {
    if (!sock_path || !token || !command || !out || out_cap == 0) return NTC_ERR_INVALID;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NTC_ERR_IO;

    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", sock_path);
    if (connect(fd, (struct sockaddr *)&un, sizeof un) < 0) { close(fd); return NTC_ERR_IO; }

    char line[2048];
    int m = snprintf(line, sizeof line, "%s %s\n", token, command);
    if (m < 0 || (size_t)m >= sizeof line) { close(fd); return NTC_ERR_OVERFLOW; }

    size_t sent = 0;
    while (sent < (size_t)m) {
        ssize_t w = write(fd, line + sent, (size_t)m - sent);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        close(fd); return NTC_ERR_IO;
    }

    size_t got = 0;
    while (got + 1 < out_cap) {
        ssize_t r = read(fd, out + got, out_cap - 1 - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0) break;
        if (errno == EINTR) continue;
        close(fd); return NTC_ERR_IO;
    }
    out[got] = '\0';
    close(fd);
    return NTC_OK;
}
