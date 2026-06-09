/* test_main.c - the unit + integration test runner (test builds only).
 *
 *   ntc_test            run all tests (alias: all)
 *   ntc_test unit       run unit tests only
 *   ntc_test it         run integration tests only (alias: integration)
 *   ntc_test list [k]   list registered tests (optionally filtered by kind)
 *   ntc_test help
 *
 * Statuses: PASS (green), FAIL (red), SKIP (yellow), TODO (cyan, planned). */
#include "ntc/test.h"
#include "ntc/color.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { ST_PASS = 0, ST_FAIL, ST_SKIP, ST_TODO };

struct ntc_test_ctx {
    int status;
    unsigned long asserts;
    const char *fail_file;
    int fail_line;
    char msg[512];
};

#ifndef NTC_TEST_MAX
#define NTC_TEST_MAX 1024
#endif

typedef struct {
    const char *suite;
    const char *name;
    const char *file;
    int line;
    ntc_test_fn fn;
    ntc_test_kind kind;
    int pending;
} ntc_test_entry;

static ntc_test_entry g_tests[NTC_TEST_MAX];
static size_t g_count;

void ntc_test_register(const char *suite, const char *name, ntc_test_fn fn,
                       const char *file, int line,
                       ntc_test_kind kind, int pending) {
    if (g_count >= NTC_TEST_MAX) {
        fprintf(stderr, "ntc_test: registry full, dropping %s.%s\n", suite, name);
        return;
    }
    g_tests[g_count] = (ntc_test_entry){
        suite, name, file, line, fn, kind, pending
    };
    g_count++;
}

void ntc_test__count(ntc_test_ctx *t) { t->asserts++; }

void ntc_test__failf(ntc_test_ctx *t, const char *file, int line,
                     const char *fmt, ...) {
    t->status = ST_FAIL;
    t->fail_file = file;
    t->fail_line = line;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t->msg, sizeof t->msg, fmt, ap);
    va_end(ap);
}

void ntc_test__skip(ntc_test_ctx *t, const char *reason) {
    t->status = ST_SKIP;
    snprintf(t->msg, sizeof t->msg, "%s", reason ? reason : "");
}

/* shorthand for "this ANSI code if stderr is colored, else nothing" */
#define C(code) ntc_colorize(STDERR_FILENO, (code))

/* -1 = all, NTC_TEST_UNIT, NTC_TEST_INTEGRATION, -2 = unknown */
static int parse_kind(const char *s) {
    if (!s || strcmp(s, "all") == 0) return -1;
    if (strcmp(s, "unit") == 0 || strcmp(s, "u") == 0) return NTC_TEST_UNIT;
    if (strcmp(s, "it") == 0 || strcmp(s, "integration") == 0 ||
        strcmp(s, "integ") == 0) return NTC_TEST_INTEGRATION;
    return -2;
}

static const char *kind_label(ntc_test_kind k) {
    return k == NTC_TEST_INTEGRATION ? "it  " : "unit";
}

static int do_list(int filt) {
    size_t shown = 0, units = 0, integ = 0, todos = 0;
    fprintf(stderr, "registered tests:\n\n");
    for (size_t i = 0; i < g_count; i++) {
        const ntc_test_entry *e = &g_tests[i];
        if (filt != -1 && (int)e->kind != filt) continue;
        shown++;
        if (e->kind == NTC_TEST_INTEGRATION) integ++; else units++;
        const char *kc = (e->kind == NTC_TEST_INTEGRATION)
                       ? NTC_ANSI_BLUE : NTC_ANSI_CYAN;
        fprintf(stderr, "  %s[%s]%s %s.%s", C(kc), kind_label(e->kind),
                C(NTC_ANSI_RESET), e->suite, e->name);
        if (e->pending) {
            todos++;
            fprintf(stderr, " %s(TODO)%s", C(NTC_ANSI_CYAN), C(NTC_ANSI_RESET));
        }
        fputc('\n', stderr);
    }
    fprintf(stderr, "\n%zu shown: %zu unit, %zu integration  (%zu todo)\n",
            shown, units, integ, todos);
    return 0;
}

static int do_run(int filt) {
    const char *what = (filt == -1) ? "all"
                     : (filt == NTC_TEST_UNIT) ? "unit" : "integration";
    fprintf(stderr, "naitron-c test runner - running %s tests\n\n", what);

    size_t pass = 0, fail = 0, skip = 0, todo = 0, selected = 0;
    unsigned long asserts = 0;

    for (size_t i = 0; i < g_count; i++) {
        const ntc_test_entry *e = &g_tests[i];
        if (filt != -1 && (int)e->kind != filt) continue;
        selected++;

        ntc_test_ctx ctx;
        memset(&ctx, 0, sizeof ctx);
        if (e->pending) {
            ctx.status = ST_TODO;
        } else {
            e->fn(&ctx);
        }
        asserts += ctx.asserts;

        switch (ctx.status) {
        case ST_FAIL:
            fail++;
            fprintf(stderr, "%s[FAIL]%s %s.%s\n         at %s:%d: %s\n",
                    C(NTC_ANSI_RED), C(NTC_ANSI_RESET), e->suite, e->name,
                    ctx.fail_file, ctx.fail_line, ctx.msg);
            break;
        case ST_SKIP:
            skip++;
            fprintf(stderr, "%s[SKIP]%s %s.%s %s(%s)%s\n",
                    C(NTC_ANSI_YELLOW), C(NTC_ANSI_RESET), e->suite, e->name,
                    C(NTC_ANSI_DIM), ctx.msg[0] ? ctx.msg : "no reason",
                    C(NTC_ANSI_RESET));
            break;
        case ST_TODO:
            todo++;
            fprintf(stderr, "%s[TODO]%s %s.%s %s(planned)%s\n",
                    C(NTC_ANSI_CYAN), C(NTC_ANSI_RESET), e->suite, e->name,
                    C(NTC_ANSI_DIM), C(NTC_ANSI_RESET));
            break;
        default:
            pass++;
            fprintf(stderr, "%s[PASS]%s %s.%s %s(%lu assertions)%s\n",
                    C(NTC_ANSI_GREEN), C(NTC_ANSI_RESET), e->suite, e->name,
                    C(NTC_ANSI_DIM), ctx.asserts, C(NTC_ANSI_RESET));
            break;
        }
    }

    fprintf(stderr,
        "\n%s%zu passed%s, %s%zu failed%s, %s%zu skipped%s, %s%zu todo%s"
        "  (%lu assertions, %zu of %zu selected)\n",
        C(NTC_ANSI_GREEN), pass, C(NTC_ANSI_RESET),
        fail ? C(NTC_ANSI_RED) : C(NTC_ANSI_DIM), fail, C(NTC_ANSI_RESET),
        skip ? C(NTC_ANSI_YELLOW) : C(NTC_ANSI_DIM), skip, C(NTC_ANSI_RESET),
        todo ? C(NTC_ANSI_CYAN) : C(NTC_ANSI_DIM), todo, C(NTC_ANSI_RESET),
        asserts, selected, g_count);

    return fail == 0 ? 0 : 1;
}

static void usage(void) {
    fprintf(stderr,
        "ntc_test - naitron-c test runner\n\n"
        "usage:\n"
        "  ntc_test [all]      run all tests\n"
        "  ntc_test unit       run unit tests only\n"
        "  ntc_test it         run integration tests only\n"
        "  ntc_test list [k]   list registered tests (k = unit|it)\n"
        "  ntc_test help\n");
}

int main(int argc, char **argv) {
    const char *cmd = (argc > 1) ? argv[1] : "all";

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 ||
        strcmp(cmd, "--help") == 0) {
        usage();
        return 0;
    }

    if (strcmp(cmd, "list") == 0 || strcmp(cmd, "ls") == 0) {
        int filt = parse_kind((argc > 2) ? argv[2] : "all");
        if (filt == -2) {
            fprintf(stderr, "ntc_test: unknown kind '%s' (use unit|it)\n", argv[2]);
            return 2;
        }
        return do_list(filt);
    }

    int filt = parse_kind(cmd);
    if (filt == -2) {
        fprintf(stderr, "ntc_test: unknown command '%s' "
                        "(try: all|unit|it|list|help)\n", cmd);
        return 2;
    }
    return do_run(filt);
}
