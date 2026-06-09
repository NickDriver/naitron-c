/* err.h - error handling foundation for naitron-c (P-0)
 *
 * Philosophy: expected failures are propagated as ntc_err values that the
 * compiler forces you to handle ([[nodiscard]]); unexpected failures are
 * isolated into restartable processes (see signal.c / the orchestrator).
 */
#ifndef NTC_ERR_H
#define NTC_ERR_H

#include <stddef.h>

/* C23 [[nodiscard]] when available, no-op otherwise. Mark every fallible
 * function with this so -Werror turns "ignored error" into a build failure. */
#if defined(__has_c_attribute)
#  if __has_c_attribute(nodiscard)
#    define NTC_NODISCARD [[nodiscard]]
#  endif
#endif
#ifndef NTC_NODISCARD
#  define NTC_NODISCARD
#endif

typedef enum ntc_err {
    NTC_OK = 0,
    NTC_ERR_OOM,        /* out of memory                         */
    NTC_ERR_IO,         /* socket / file I/O failure             */
    NTC_ERR_PARSE,      /* malformed input                       */
    NTC_ERR_INVALID,    /* invalid argument / precondition       */
    NTC_ERR_OVERFLOW,   /* integer / size overflow               */
    NTC_ERR_NOT_FOUND,  /* route / resource not found            */
    NTC_ERR_TIMEOUT,    /* operation timed out                   */
    NTC_ERR_AGAIN,      /* would block, retry later              */
    NTC_ERR_INTERNAL,   /* unexpected internal error             */
    NTC_ERR__COUNT
} ntc_err;

/* Stable symbolic name, e.g. "NTC_ERR_OOM". Never NULL. */
const char *ntc_err_str(ntc_err e);

/* Map an internal error to the HTTP status it should surface as. */
int ntc_err_http_status(ntc_err e);

/* `?`-style propagation: evaluate expr; if it is an error, return it up. */
#define NTC_TRY(expr)                          \
    do {                                       \
        ntc_err ntc__e = (expr);               \
        if (ntc__e != NTC_OK) return ntc__e;   \
    } while (0)

#ifndef NTC_NO_SHORT_MACROS
#  define TRY NTC_TRY
#endif

/* Overflow-checked size arithmetic. Always returns a value you must use the
 * out-param of; on wrap, returns NTC_ERR_OVERFLOW and leaves *out unspecified.
 * Critical for any allocation sized from attacker-controlled lengths. */
static inline ntc_err ntc_size_mul(size_t a, size_t b, size_t *out) {
    if (__builtin_mul_overflow(a, b, out)) return NTC_ERR_OVERFLOW;
    return NTC_OK;
}
static inline ntc_err ntc_size_add(size_t a, size_t b, size_t *out) {
    if (__builtin_add_overflow(a, b, out)) return NTC_ERR_OVERFLOW;
    return NTC_OK;
}

#endif /* NTC_ERR_H */
