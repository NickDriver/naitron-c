/* main.c - the `ntc` CLI entrypoint.
 *
 * `start` is the daemon; the other subcommands are control clients that connect
 * to the running core's authenticated control socket. */
#define _GNU_SOURCE
#include "ntc/arena.h"
#include "ntc/color.h"
#include "ntc/control.h"
#include "ntc/err.h"
#include "ntc/json.h"
#include "ntc/log.h"
#include "ntc/mcp.h"
#include "ntc/server.h"
#include "ntc/signal.h"
#include "ntc/slice.h"
#include "ntc/version.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NTC_DASHBOARD_DEFAULT 9090

__attribute__((format(printf, 1, 2)))
static void cli_errorf(const char *fmt, ...) {
    fprintf(stderr, "%serror:%s ", ntc_colorize(STDERR_FILENO, NTC_ANSI_RED),
            ntc_colorize(STDERR_FILENO, NTC_ANSI_RESET));
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}

static void usage(const char *p) {
    fprintf(stderr,
        NTC_NAME " " NTC_VERSION " - microkernel web framework\n\n"
        "usage:\n"
        "  %s start <port> [-d] [--dashboard <port>|--no-dashboard] [--tls <port>]\n"
        "                                                             start the core\n"
        "  %s dev <port> [--build \"<cmd>\"] [--watch <path>]... [--tls <port>]\n"
        "                                          foreground + mtime hot-reload\n"
        "  %s stop | restart <port>                                   stop / restart\n"
        "  %s logs [-f]                                               tail the log\n"
        "  %s status [--json]                                         core status\n"
        "  %s service add <name> <bin> | list [--json] | rm <name> | scale <name> <n>\n"
        "  %s route add <METHOD> <path> <svc> | list [--json]\n"
        "  %s config set <key> <value> | get <key>\n"
        "  %s mcp [tools|help]                                        MCP stdio server\n"
        "  %s token | version | help\n",
        p, p, p, p, p, p, p, p, p, p);
}

static bool has_flag(int argc, char **argv, const char *flag) {
    for (int i = 2; i < argc; i++) if (strcmp(argv[i], flag) == 0) return true;
    return false;
}

static int parse_port(const char *s, uint16_t *out) {
    errno = 0; char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > 65535) return -1;
    *out = (uint16_t)v; return 0;
}

static void sleep_ms(int ms) { struct timespec t = { ms / 1000, (long)(ms % 1000) * 1000000 }; nanosleep(&t, NULL); }

/* ---- pid/log files ---- */
static const char *pidfile_path(void) { const char *p = getenv("NTC_PID_FILE"); return p ? p : "./ntc.pid"; }
static const char *logfile_path(void) { const char *p = getenv("NTC_LOG_FILE"); return p ? p : "./ntc.log"; }
static int read_pidfile(void) {
    FILE *f = fopen(pidfile_path(), "r"); if (!f) return -1;
    int pid = -1; if (fscanf(f, "%d", &pid) != 1) pid = -1; fclose(f); return pid;
}
static void write_pidfile(int pid) { FILE *f = fopen(pidfile_path(), "w"); if (f) { fprintf(f, "%d\n", pid); fclose(f); } }
static bool pid_alive(int pid) { return pid > 0 && kill(pid, 0) == 0; }

/* ---- control client ---- */
static int do_control_raw(const char *command, char *out, size_t cap) {
    char token[65];
    if (ntc_control_read_token(token, sizeof token) != NTC_OK) {
        cli_errorf("no control token (is `%s start` running? set NTC_TOKEN)", NTC_NAME); return 2;
    }
    if (ntc_control_call(ntc_control_sock_path(), token, command, out, cap) != NTC_OK) {
        cli_errorf("cannot reach control socket '%s' (is the core running?)", ntc_control_sock_path()); return 2;
    }
    return strncmp(out, "OK", 2) == 0 ? 0 : 1;
}

/* print raw reply (default for mutating commands) */
static int do_control(const char *command) {
    char out[8192]; int rc = do_control_raw(command, out, sizeof out);
    if (rc == 2) return 2;
    fputs(out, stdout);
    size_t n = strlen(out); if (n == 0 || out[n - 1] != '\n') fputc('\n', stdout);
    return rc;
}

/* ---- formatted output ---- */
static const char *ok_json(const char *out) { return strncmp(out, "OK ", 3) == 0 ? out + 3 : out; }

static void fmt_uptime(long s, char *buf, size_t cap) {
    if (s < 60) snprintf(buf, cap, "%lds", s);
    else if (s < 3600) snprintf(buf, cap, "%ldm", s / 60);
    else snprintf(buf, cap, "%ldh%ldm", s / 3600, (s % 3600) / 60);
}

static int cmd_status(int argc, char **argv) {
    char out[8192]; int rc = do_control_raw("status", out, sizeof out);
    if (rc == 2) return 2;
    if (has_flag(argc, argv, "--json")) { printf("%s\n", ok_json(out)); return rc; }

    ntc_arena a; if (ntc_arena_init(&a, 8192) != NTC_OK) return 1;
    ntc_json *v = ntc_json_parse(&a, ok_json(out), strlen(ok_json(out)));
    if (!v) { fputs(out, stdout); ntc_arena_destroy(&a); return rc; }

    char up[32]; fmt_uptime((long)ntc_json_num(ntc_json_get(v, "uptime_s")), up, sizeof up);
    ntc_slice app = ntc_json_str(ntc_json_get(v, "app"));
    ntc_slice be = ntc_json_str(ntc_json_get(v, "backend"));
    const char *grn = ntc_colorize(STDOUT_FILENO, NTC_ANSI_GREEN);
    const char *dim = ntc_colorize(STDOUT_FILENO, NTC_ANSI_DIM);
    const char *rst = ntc_colorize(STDOUT_FILENO, NTC_ANSI_RESET);
    printf("%.*s   %s\xe2\x97\x8f running%s   up %s   backend %.*s\n",
           (int)app.len, app.ptr, grn, rst, up, (int)be.len, be.ptr);
    printf("%sservices%s %d   %sroutes%s %d\n", dim, rst, (int)ntc_json_num(ntc_json_get(v, "services")),
           dim, rst, (int)ntc_json_num(ntc_json_get(v, "routes")));
    printf("%srequests%s %d   2xx %d   4xx %d   5xx %d   (fwd %d, builtin %d)\n",
           dim, rst, (int)ntc_json_num(ntc_json_get(v, "requests")),
           (int)ntc_json_num(ntc_json_get(v, "status_2xx")),
           (int)ntc_json_num(ntc_json_get(v, "status_4xx")),
           (int)ntc_json_num(ntc_json_get(v, "status_5xx")),
           (int)ntc_json_num(ntc_json_get(v, "forwarded")),
           (int)ntc_json_num(ntc_json_get(v, "builtin")));
    ntc_arena_destroy(&a);
    return rc;
}

static int cmd_list(const char *command, const char *cols[], const char *keys[],
                    int ncol, int argc, char **argv) {
    char out[16384]; int rc = do_control_raw(command, out, sizeof out);
    if (rc == 2) return 2;
    if (has_flag(argc, argv, "--json")) { printf("%s\n", ok_json(out)); return rc; }

    ntc_arena a; if (ntc_arena_init(&a, 16384) != NTC_OK) return 1;
    ntc_json *arr = ntc_json_parse(&a, ok_json(out), strlen(ok_json(out)));
    if (!arr || arr->type != NTC_JSON_ARR) { fputs(out, stdout); ntc_arena_destroy(&a); return rc; }

    if (arr->count == 0) { printf("(none)\n"); ntc_arena_destroy(&a); return rc; }
    const char *dim = ntc_colorize(STDOUT_FILENO, NTC_ANSI_DIM);
    const char *rst = ntc_colorize(STDOUT_FILENO, NTC_ANSI_RESET);
    for (int ci = 0; ci < ncol; ci++) printf("%s%-22s%s", dim, cols[ci], rst);
    printf("\n");
    for (size_t i = 0; i < arr->count; i++) {
        for (int ci = 0; ci < ncol; ci++) {
            ntc_slice s = ntc_json_str(ntc_json_get(arr->items[i], keys[ci]));
            printf("%-22.*s", (int)s.len, s.ptr);
        }
        printf("\n");
    }
    ntc_arena_destroy(&a);
    return rc;
}

/* ---- start / stop / restart / logs ---- */
static int run_start(const char *prog, int argc, char **argv) {
    if (argc < 3) { cli_errorf("'start' needs a port, e.g. `%s start 3000`", prog); return 2; }
    uint16_t port = 0;
    if (parse_port(argv[2], &port) != 0) { cli_errorf("invalid port '%s' (1-65535)", argv[2]); return 2; }

    uint16_t dash = NTC_DASHBOARD_DEFAULT;
    uint16_t tls_port = 0;
    bool detach = false;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--detach") == 0) detach = true;
        else if (strcmp(argv[i], "--no-dashboard") == 0) dash = 0;
        else if ((strcmp(argv[i], "--dashboard") == 0 || strcmp(argv[i], "--admin") == 0) && i + 1 < argc) {
            if (parse_port(argv[++i], &dash) != 0) { cli_errorf("invalid dashboard port '%s'", argv[i]); return 2; }
        } else if (strcmp(argv[i], "--tls") == 0 && i + 1 < argc) {
            if (parse_port(argv[++i], &tls_port) != 0) { cli_errorf("invalid TLS port '%s'", argv[i]); return 2; }
        } else { cli_errorf("unknown argument '%s'", argv[i]); return 2; }
    }

    int existing = read_pidfile();
    if (pid_alive(existing)) { cli_errorf("already running (pid %d) - `%s stop` first", existing, prog); return 1; }

    if (detach) {
        pid_t pid = fork();
        if (pid < 0) { cli_errorf("fork failed: %s", strerror(errno)); return 1; }
        if (pid > 0) { write_pidfile(pid); printf("started (pid %d) \xc2\xb7 logs: %s\n", pid, logfile_path()); return 0; }
        setsid();
        int fd = open(logfile_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
        int nul = open("/dev/null", O_RDONLY); if (nul >= 0) { dup2(nul, 0); close(nul); }
    } else {
        write_pidfile(getpid());
    }

    ntc_err e = ntc_server_run(port, dash, tls_port, NULL);
    unlink(pidfile_path());
    if (e != NTC_OK) { NTC_ERROR("server exited: %s", ntc_err_str(e)); return 1; }
    return 0;
}

/* `dev` runs the gateway in the foreground with mtime hot-reload: edit a
 * controller, rebuild (manually or via --build), and the gateway respawns it. */
static int run_dev(const char *prog, int argc, char **argv) {
    if (argc < 3) { cli_errorf("'dev' needs a port, e.g. `%s dev 3000`", prog); return 2; }
    uint16_t port = 0;
    if (parse_port(argv[2], &port) != 0) { cli_errorf("invalid port '%s' (1-65535)", argv[2]); return 2; }

    uint16_t dash = NTC_DASHBOARD_DEFAULT;
    uint16_t tls_port = 0;
    const char *build = NULL;
    const char *paths[NTC_DEV_MAX_WATCH];
    size_t npaths = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--no-dashboard") == 0) dash = 0;
        else if ((strcmp(argv[i], "--dashboard") == 0 || strcmp(argv[i], "--admin") == 0) && i + 1 < argc) {
            if (parse_port(argv[++i], &dash) != 0) { cli_errorf("invalid dashboard port '%s'", argv[i]); return 2; }
        } else if (strcmp(argv[i], "--tls") == 0 && i + 1 < argc) {
            if (parse_port(argv[++i], &tls_port) != 0) { cli_errorf("invalid TLS port '%s'", argv[i]); return 2; }
        } else if (strcmp(argv[i], "--build") == 0 && i + 1 < argc) {
            build = argv[++i];
        } else if (strcmp(argv[i], "--watch") == 0 && i + 1 < argc) {
            if (npaths >= NTC_DEV_MAX_WATCH) { cli_errorf("too many --watch paths (max %d)", NTC_DEV_MAX_WATCH); return 2; }
            paths[npaths++] = argv[++i];
        } else { cli_errorf("unknown argument '%s'", argv[i]); return 2; }
    }
    /* a build hook with no explicit --watch defaults to the usual source roots */
    if (build && npaths == 0) {
        if (access("controllers", F_OK) == 0) paths[npaths++] = "controllers";
        if (access("src", F_OK) == 0) paths[npaths++] = "src";
    }

    int existing = read_pidfile();
    if (pid_alive(existing)) { cli_errorf("already running (pid %d) - `%s stop` first", existing, prog); return 1; }
    write_pidfile(getpid());

    ntc_dev_opts opts = { .watch = true, .build_cmd = build, .paths = paths, .npaths = npaths };
    ntc_err e = ntc_server_run(port, dash, tls_port, &opts);
    unlink(pidfile_path());
    if (e != NTC_OK) { NTC_ERROR("server exited: %s", ntc_err_str(e)); return 1; }
    return 0;
}

static int cmd_stop(void) {
    char out[1024];
    int rc = do_control_raw("stop", out, sizeof out);
    if (rc != 2) { fputs(out, stdout); return rc; }
    int pid = read_pidfile();
    if (pid_alive(pid)) { kill(pid, SIGTERM); printf("sent SIGTERM to pid %d\n", pid); return 0; }
    cli_errorf("core does not appear to be running"); return 1;
}

static int cmd_logs(int argc, char **argv) {
    bool follow = has_flag(argc, argv, "-f") || has_flag(argc, argv, "--follow");
    FILE *f = fopen(logfile_path(), "r");
    if (!f) { cli_errorf("no log file at %s", logfile_path()); return 1; }
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
    while (follow) {
        clearerr(f);
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
        fflush(stdout);
        sleep_ms(250);
    }
    fclose(f);
    return 0;
}

static int cmd_new_controller(const char *prog, const char *name) {
    for (const char *p = name; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_')) { cli_errorf("invalid name '%s' (use a-z0-9_)", name); return 1; }
    char path[256];
    snprintf(path, sizeof path, "controllers/%s_controller.c", name);
    if (access(path, F_OK) == 0) { cli_errorf("%s already exists", path); return 1; }
    FILE *f = fopen(path, "w");
    if (!f) { cli_errorf("cannot write %s: %s", path, strerror(errno)); return 1; }
    fprintf(f,
        "#define _GNU_SOURCE\n"
        "#include \"ntc/controller.h\"\n\n"
        "#include <unistd.h>\n\n"
        "static int handle(const ntc_request *req, ntc_response *res, ntc_arena *a, void *u) {\n"
        "    (void)u;\n"
        "    /* helpers: ntc_req_param(req,\"id\"), ntc_req_query(req,\"page\"),\n"
        "     *          ntc_http_header(req,\"...\"), req->body, req->auth_sub */\n"
        "    return ntc_reply_json(res, a, 200,\n"
        "        \"{\\\"controller\\\":\\\"%s\\\",\\\"path\\\":\\\"%%.*s\\\"}\",\n"
        "        (int)req->path.len, req->path.ptr);\n"
        "}\n\n"
        "int main(void) {\n"
        "    ntc_controller ctl = { .name = \"%s\", .handle = handle, .udata = NULL };\n"
        "    return ntc_controller_run(&ctl);\n"
        "}\n",
        name, name);
    fclose(f);
    printf("created %s\n\n", path);
    printf("build:\n  clang -std=c23 -Iinclude %s \\\n", path);
    printf("    src/common/controller_sdk.c src/common/wire.c src/common/arena.c \\\n");
    printf("    src/common/slice.c src/common/http_request.c -o build/%s_controller\n\n", name);
    printf("register (on a running core):\n  %s service add %s ./build/%s_controller\n"
           "  %s route add GET /api/%s %s\n", prog, name, name, prog, name, name);
    return 0;
}

int main(int argc, char **argv) {
    ntc_install_signal_handlers();
    const char *prog = (argc > 0) ? argv[0] : NTC_NAME;
    if (argc < 2) { usage(prog); return 2; }
    const char *cmd = argv[1];
    char buf[2048];

    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) { printf(NTC_NAME " %s\n", NTC_VERSION); return 0; }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) { usage(prog); return 0; }
    if (strcmp(cmd, "start") == 0) return run_start(prog, argc, argv);
    if (strcmp(cmd, "dev") == 0) return run_dev(prog, argc, argv);
    if (strcmp(cmd, "stop") == 0) return cmd_stop();
    if (strcmp(cmd, "logs") == 0) return cmd_logs(argc, argv);
    if (strcmp(cmd, "status") == 0) return cmd_status(argc, argv);
    if (strcmp(cmd, "new") == 0) {
        if (argc < 4 || strcmp(argv[2], "controller") != 0) { cli_errorf("usage: %s new controller <name>", prog); return 2; }
        return cmd_new_controller(prog, argv[3]);
    }

    if (strcmp(cmd, "restart") == 0) {
        if (argc < 3) { cli_errorf("usage: %s restart <port>", prog); return 2; }
        char out[1024]; (void)do_control_raw("stop", out, sizeof out);
        int pid = read_pidfile();
        for (int i = 0; i < 50 && pid_alive(pid); i++) sleep_ms(100);
        char *a[] = { (char *)prog, "start", argv[2], "-d", NULL };
        return run_start(prog, 4, a);
    }

    if (strcmp(cmd, "mcp") == 0) {
        const char *sub = argc > 2 ? argv[2] : "";
        if (sub[0] == '\0') return ntc_mcp_run();
        if (strcmp(sub, "tools") == 0) { ntc_mcp_print_tools(has_flag(argc, argv, "--json")); return 0; }
        if (strcmp(sub, "help") == 0) {
            printf("naitron-c MCP server.\n  %s mcp         run the stdio JSON-RPC server\n"
                   "  %s mcp tools   list available tools\n", prog, prog);
            return 0;
        }
        cli_errorf("unknown mcp subcommand '%s'", sub); return 2;
    }

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
            snprintf(buf, sizeof buf, "service-add %s %s", argv[3], argv[4]); return do_control(buf);
        }
        if (strcmp(sub, "list") == 0) {
            const char *cols[] = { "NAME", "BIN" }, *keys[] = { "name", "bin" };
            return cmd_list("service-list", cols, keys, 2, argc, argv);
        }
        if (strcmp(sub, "rm") == 0) {
            if (argc < 4) { cli_errorf("usage: %s service rm <name>", prog); return 2; }
            snprintf(buf, sizeof buf, "service-rm %s", argv[3]); return do_control(buf);
        }
        if (strcmp(sub, "scale") == 0) {
            if (argc < 5) { cli_errorf("usage: %s service scale <name> <replicas>", prog); return 2; }
            snprintf(buf, sizeof buf, "service-scale %s %s", argv[3], argv[4]); return do_control(buf);
        }
        cli_errorf("unknown service subcommand '%s'", sub); return 2;
    }

    if (strcmp(cmd, "route") == 0) {
        const char *sub = argc > 2 ? argv[2] : "";
        if (strcmp(sub, "add") == 0) {
            if (argc < 6) { cli_errorf("usage: %s route add <METHOD> <path> <service>", prog); return 2; }
            snprintf(buf, sizeof buf, "route-add %s %s %s", argv[3], argv[4], argv[5]); return do_control(buf);
        }
        if (strcmp(sub, "list") == 0) {
            const char *cols[] = { "METHOD", "PATTERN", "SERVICE" }, *keys[] = { "method", "pattern", "service" };
            return cmd_list("route-list", cols, keys, 3, argc, argv);
        }
        cli_errorf("unknown route subcommand '%s'", sub); return 2;
    }

    if (strcmp(cmd, "config") == 0) {
        const char *sub = argc > 2 ? argv[2] : "";
        if (strcmp(sub, "set") == 0) {
            if (argc < 5) { cli_errorf("usage: %s config set <key> <value>", prog); return 2; }
            int off = snprintf(buf, sizeof buf, "config-set %s", argv[3]);
            for (int i = 4; i < argc && off < (int)sizeof buf - 2; i++)
                off += snprintf(buf + off, sizeof buf - (size_t)off, "%s%s", i == 4 ? " " : " ", argv[i]);
            return do_control(buf);
        }
        if (strcmp(sub, "get") == 0) {
            if (argc < 4) { cli_errorf("usage: %s config get <key>", prog); return 2; }
            snprintf(buf, sizeof buf, "config-get %s", argv[3]); return do_control(buf);
        }
        cli_errorf("unknown config subcommand '%s'", sub); return 2;
    }

    cli_errorf("unknown command '%s'", cmd);
    fputc('\n', stderr);
    usage(prog);
    return 2;
}
