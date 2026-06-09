/* main.c - the `ntc` CLI entrypoint.
 *
 * P0 ships only `start`; `route`, `service`, `keys`, `new`, etc. arrive with
 * the control plane (P6/P7). `start` becomes the daemon; future subcommands
 * will be thin control clients over the authenticated control socket. */
#include "ntc/color.h"
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
        "  %s start <port> [--admin <port>]   start the gateway/core\n"
        "  %s version                         print version and exit\n"
        "  %s help                            show this help\n",
        prog, prog, prog);
}

static int parse_port(const char *s, uint16_t *out) {
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > 65535)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

int main(int argc, char **argv) {
    ntc_install_signal_handlers();

    const char *prog = (argc > 0) ? argv[0] : NTC_NAME;
    if (argc < 2) {
        usage(prog);
        return 2;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) {
        printf(NTC_NAME " %s\n", NTC_VERSION);
        return 0;
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "-h") == 0) {
        usage(prog);
        return 0;
    }

    if (strcmp(cmd, "start") == 0) {
        if (argc < 3) {
            cli_errorf("'start' needs a port, e.g. `%s start 3000`", prog);
            return 2;
        }
        uint16_t port = 0;
        if (parse_port(argv[2], &port) != 0) {
            cli_errorf("invalid port '%s' (must be 1-65535)", argv[2]);
            return 2;
        }

        uint16_t admin_port = 0;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--admin") == 0 && i + 1 < argc) {
                if (parse_port(argv[++i], &admin_port) != 0) {
                    cli_errorf("invalid --admin port '%s'", argv[i]);
                    return 2;
                }
            } else {
                cli_errorf("unknown argument '%s'", argv[i]);
                return 2;
            }
        }

        ntc_err e = ntc_server_run(port, admin_port);
        if (e != NTC_OK) {
            NTC_ERROR("server exited with error: %s", ntc_err_str(e));
            return 1;
        }
        return 0;
    }

    cli_errorf("unknown command '%s'", cmd);
    fputc('\n', stderr);
    usage(prog);
    return 2;
}
