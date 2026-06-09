/* test.h - in-file + integration test harness for naitron-c.
 *
 * Unit tests live at the bottom of any .c under #ifdef UNIT_TEST:
 *
 *     TEST(arena, alloc)      { ASSERT_NOT_NULL(p); }   // white-box, in-file
 *     TEST_TODO(http, parse)  { }                       // planned, not run
 *
 * Integration tests live in the tests/ directory (always test-only):
 *
 *     ITEST(gateway, http_200)     { ... }              // black-box, spans procs
 *     ITEST_TODO(gateway, ipc)     { }                  // planned
 *
 * Inside any test body, SKIP("reason") skips at runtime (does not fail).
 * Every TEST/ITEST variant auto-registers via __attribute__((constructor)).
 * The runner (test_main.c) provides main() and supports subcommands:
 *   ntc_test [all] | unit | it | list
 */
#ifndef NTC_TEST_H
#define NTC_TEST_H

#include <stddef.h>

typedef struct ntc_test_ctx ntc_test_ctx;
typedef void (*ntc_test_fn)(ntc_test_ctx *t);

typedef enum ntc_test_kind {
    NTC_TEST_UNIT = 0,
    NTC_TEST_INTEGRATION = 1
} ntc_test_kind;

void ntc_test_register(const char *suite, const char *name, ntc_test_fn fn,
                       const char *file, int line,
                       ntc_test_kind kind, int pending);

/* internal hooks used by the macros below */
void ntc_test__count(ntc_test_ctx *t);
void ntc_test__failf(ntc_test_ctx *t, const char *file, int line,
                     const char *fmt, ...) __attribute__((format(printf, 4, 5)));
void ntc_test__skip(ntc_test_ctx *t, const char *reason);

#define NTC_TEST_DEFINE_(suite, name, kind, pending)                           \
    static void ntc_test_fn_##suite##_##name(ntc_test_ctx *t);                 \
    __attribute__((constructor))                                               \
    static void ntc_test_reg_##suite##_##name(void) {                          \
        ntc_test_register(#suite, #name, ntc_test_fn_##suite##_##name,          \
                          __FILE__, __LINE__, (kind), (pending));               \
    }                                                                          \
    static void ntc_test_fn_##suite##_##name([[maybe_unused]] ntc_test_ctx *t)

#define TEST(suite, name)       NTC_TEST_DEFINE_(suite, name, NTC_TEST_UNIT, 0)
#define ITEST(suite, name)      NTC_TEST_DEFINE_(suite, name, NTC_TEST_INTEGRATION, 0)
#define TEST_TODO(suite, name)  NTC_TEST_DEFINE_(suite, name, NTC_TEST_UNIT, 1)
#define ITEST_TODO(suite, name) NTC_TEST_DEFINE_(suite, name, NTC_TEST_INTEGRATION, 1)

/* Skip the current test at runtime with a reason; does not fail the suite. */
#define SKIP(reason)                                                           \
    do { ntc_test__skip(t, (reason)); return; } while (0)

#define ASSERT_TRUE(cond)                                                      \
    do {                                                                       \
        ntc_test__count(t);                                                    \
        if (!(cond)) {                                                         \
            ntc_test__failf(t, __FILE__, __LINE__,                             \
                            "ASSERT_TRUE failed: %s", #cond);                  \
            return;                                                            \
        }                                                                      \
    } while (0)

#define ASSERT_FALSE(cond)                                                     \
    do {                                                                       \
        ntc_test__count(t);                                                    \
        if ((cond)) {                                                          \
            ntc_test__failf(t, __FILE__, __LINE__,                             \
                            "ASSERT_FALSE failed: %s", #cond);                 \
            return;                                                            \
        }                                                                      \
    } while (0)

#define ASSERT_EQ_INT(expected, actual)                                        \
    do {                                                                       \
        ntc_test__count(t);                                                    \
        long long ntc__e = (long long)(expected);                             \
        long long ntc__a = (long long)(actual);                               \
        if (ntc__e != ntc__a) {                                               \
            ntc_test__failf(t, __FILE__, __LINE__,                             \
                "ASSERT_EQ_INT failed: %s == %s (%lld != %lld)",               \
                #expected, #actual, ntc__e, ntc__a);                          \
            return;                                                            \
        }                                                                      \
    } while (0)

#define ASSERT_EQ_UINT(expected, actual)                                       \
    do {                                                                       \
        ntc_test__count(t);                                                    \
        unsigned long long ntc__e = (unsigned long long)(expected);           \
        unsigned long long ntc__a = (unsigned long long)(actual);             \
        if (ntc__e != ntc__a) {                                               \
            ntc_test__failf(t, __FILE__, __LINE__,                             \
                "ASSERT_EQ_UINT failed: %s == %s (%llu != %llu)",              \
                #expected, #actual, ntc__e, ntc__a);                          \
            return;                                                            \
        }                                                                      \
    } while (0)

#define ASSERT_NOT_NULL(p)                                                     \
    do {                                                                       \
        ntc_test__count(t);                                                    \
        if ((p) == NULL) {                                                     \
            ntc_test__failf(t, __FILE__, __LINE__,                             \
                            "ASSERT_NOT_NULL failed: %s", #p);                 \
            return;                                                            \
        }                                                                      \
    } while (0)

#define ASSERT_NULL(p)                                                         \
    do {                                                                       \
        ntc_test__count(t);                                                    \
        if ((p) != NULL) {                                                     \
            ntc_test__failf(t, __FILE__, __LINE__,                             \
                            "ASSERT_NULL failed: %s", #p);                     \
            return;                                                            \
        }                                                                      \
    } while (0)

#endif /* NTC_TEST_H */
