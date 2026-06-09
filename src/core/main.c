/* main.c - the `ntc` CLI entrypoint.
 *
 * `start` is the daemon; the other subcommands are control clients that connect
 * to the running core's authenticated control socket. */
#include "ntc/color.h"
#include "ntc/control.h"
#include "ntc/err.h"
#include "ntc/log.h"
#include "ntc/server.h"
#include "ntc/signal.h"
#include "ntc/version.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((format(printf, 1, 2)))
static void cli_errorf(const char *fmt, ...) {
    fprintf(stderr, "%serror:%s ",
            ntc_colorize(STDERR_FILENO, NTC_ANSI_RED),
            ntc_colorize(STDERR_FILENO, NTC_ANSI_RESET));
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void usage(const char *prog) {
    fprintf(stderr,
        NTC_NAME " " NTC_VERSION " - microkernel web framework\n"
        "\n"
        "usage:\n"
        "  %s start <port> [--admin <port>]      start the gateway/core\n"
        "  %s status                             show core status\n"
        "  %s service add <name> <bin>           register + spawn a controller (live)\n"
        "  %s service list                       list registered services\n"
        "  %s service rm <name>                  remove a service\n"
        "  %s route add <METHOD> <path> <svc>    route a path to a service (live)\n"
        "  %s route list                         list routes\n"
        "  %s stop                               stop the running core\n"
        "  %s token                              print the control token + socket\n"
        "  %s version | help\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static int parse_port(const char *s, uint16_t *out) {
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > 65535) return -1;
    *out = (uint16_t)v;
    return 0;
}

/* Send a control command to the running core; print the reply. */
static int do_control(const char *command) {
    char token[65];
    if (ntc_control_read_token(token, sizeof token) != NTC_OK) {
        cli_errorf("no control token (is the core running? set NTC_TOKEN / NTC_TOKEN_FILE)");
        return 2;
    }
    char out[8192];
    if (ntc_control_call(ntc_control_sock_path(), token, command, out, sizeof out) != NTC_OK) {
        cli_errorf("cannot reach control socket '%s' (is `%s start` running?)",
                   ntc_control_sock_path(), NTC_NAME);
        return 2;
    }
    fputs(out, stdout);
    size_t n = strlen(out);
    if (n == 0 || out[n - 1] != '\n') fputc('\n', stdout);
    return strncmp(out, "OK", 2) == 0 ? 0 : 1;
}

static int run_start(const char *prog, int argc, char **argv) {
    if (argc < 3) { cli_errorf("'start' needs a port, e.g. `%s start 3000`", prog); return 2; }
    uint16_t port = 0;
    if (parse_port(argv[2], &port) != 0) { cli_errorf("invalid port '%s' (1-65535)", argv[2]); return 2; }
    uint16_t admin_port = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--admin") == 0 && i + 1 < argc) {
            if (parse_port(argv[++i], &admin_port) != 0) { cli_errorf("invalid --admin port '%s'", argv[i]); return 2; }
        } else { cli_errorf("unknown argument '%s'", argv[i]); return 2; }
    }
    ntc_err e = ntc_server_run(port, admin_port);
    if (e != NTC_OK) { NTC_ERROR("server exited: %s", ntc_err_str(e)); return 1; }
    return 0;
}

int main(int argc, char **argv) {
    ntc_install_signal_handlers();

    const char *prog = (argc > 0) ? argv[0] : NTC_NAME;
    if (argc < 2) { usage(prog); return 2; }
    const char *cmd = argv[1];
    char buf[1024];

    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) {
        printf(NTC_NAME " %s\n", NTC_VERSION);
        return 0;
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(prog);
        return 0;
    }
    if (strcmp(cmd, "start") == 0) return run_start(prog, argc, argv);
    if (strcmp(cmd, "status") == 0) return do_control("status");
    if (strcmp(cmd, "stop") == 0) return do_control("stop");

    if (strcmp(cmd, "token") == 0) {
        char token[65];
        if (ntc_control_read_token(token, sizeof token) != NTC_OK) { cli_errorf("no token found"); return 1; }
        printf("token:  %s\nsocket: %s\n", token, ntc_control_sock_path());
        return 0;
    }

    if (strcmp(cmd, "service") == 0) {
        const char *sub = argc > 2 ? argv[2] : "";
        if (strcmp(sub, "add") == 0) {
            if (argc < 5) { cli_errorf("usage: %s service add <name> <bin>", prog); return 2; }
            snprintf(buf, sizeof buf, "service-add %s %s", argv[3], argv[4]);
            return do_control(buf);
        }
        if (strcmp(sub, "list") == 0) return do_control("service-list");
        if (strcmp(sub, "rm") == 0) {
            if (argc < 4) { cli_errorf("usage: %s service rm <name>", prog); return 2; }
            snprintf(buf, sizeof buf, "service-rm %s", argv[3]);
            return do_control(buf);
        }
        cli_errorf("unknown service subcommand '%s'", sub);
        return 2;
    }

    if (strcmp(cmd, "route") == 0) {
        const char *sub = argc > 2 ? argv[2] : "";
        if (strcmp(sub, "add") == 0) {
            if (argc < 6) { cli_errorf("usage: %s route add <METHOD> <path> <service>", prog); return 2; }
            snprintf(buf, sizeof buf, "route-add %s %s %s", argv[3], argv[4], argv[5]);
            return do_control(buf);
        }
        if (strcmp(sub, "list") == 0) return do_control("route-list");
        cli_errorf("unknown route subcommand '%s'", sub);
        return 2;
    }

    cli_errorf("unknown command '%s'", cmd);
    fputc('\n', stderr);
    usage(prog);
    return 2;
}
