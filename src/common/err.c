#include "ntc/err.h"

#include <stdint.h>
#include <string.h>

const char *ntc_err_str(ntc_err e) {
    switch (e) {
        case NTC_OK:            return "NTC_OK";
        case NTC_ERR_OOM:       return "NTC_ERR_OOM";
        case NTC_ERR_IO:        return "NTC_ERR_IO";
        case NTC_ERR_PARSE:     return "NTC_ERR_PARSE";
        case NTC_ERR_INVALID:   return "NTC_ERR_INVALID";
        case NTC_ERR_OVERFLOW:  return "NTC_ERR_OVERFLOW";
        case NTC_ERR_NOT_FOUND: return "NTC_ERR_NOT_FOUND";
        case NTC_ERR_TIMEOUT:   return "NTC_ERR_TIMEOUT";
        case NTC_ERR_AGAIN:     return "NTC_ERR_AGAIN";
        case NTC_ERR_INTERNAL:  return "NTC_ERR_INTERNAL";
        case NTC_ERR__COUNT:    break;
    }
    return "NTC_ERR_UNKNOWN";
}

int ntc_err_http_status(ntc_err e) {
    switch (e) {
        case NTC_OK:            return 200;
        case NTC_ERR_PARSE:     return 400;
        case NTC_ERR_INVALID:   return 400;
        case NTC_ERR_OVERFLOW:  return 400;
        case NTC_ERR_NOT_FOUND: return 404;
        case NTC_ERR_TIMEOUT:   return 504;
        case NTC_ERR_OOM:       return 503;
        case NTC_ERR_AGAIN:     return 503;
        case NTC_ERR_IO:        return 502;
        case NTC_ERR_INTERNAL:  return 500;
        case NTC_ERR__COUNT:    break;
    }
    return 500;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(err, str_nonempty_for_all) {
    for (int e = 0; e < NTC_ERR__COUNT; e++) {
        const char *s = ntc_err_str((ntc_err)e);
        ASSERT_NOT_NULL(s);
        ASSERT_TRUE(strlen(s) > 0);
    }
}

TEST(err, http_status_mapping) {
    ASSERT_EQ_INT(200, ntc_err_http_status(NTC_OK));
    ASSERT_EQ_INT(400, ntc_err_http_status(NTC_ERR_PARSE));
    ASSERT_EQ_INT(404, ntc_err_http_status(NTC_ERR_NOT_FOUND));
    ASSERT_EQ_INT(504, ntc_err_http_status(NTC_ERR_TIMEOUT));
    ASSERT_EQ_INT(502, ntc_err_http_status(NTC_ERR_IO));
    ASSERT_EQ_INT(500, ntc_err_http_status(NTC_ERR_INTERNAL));
}

TEST(err, size_mul_checks_overflow) {
    size_t out = 0;
    ASSERT_EQ_INT(NTC_OK, ntc_size_mul(12, 10, &out));
    ASSERT_EQ_UINT(120u, out);
    ASSERT_EQ_INT(NTC_ERR_OVERFLOW, ntc_size_mul(SIZE_MAX, 2, &out));
}

TEST(err, size_add_checks_overflow) {
    size_t out = 0;
    ASSERT_EQ_INT(NTC_OK, ntc_size_add(40, 2, &out));
    ASSERT_EQ_UINT(42u, out);
    ASSERT_EQ_INT(NTC_ERR_OVERFLOW, ntc_size_add(SIZE_MAX, 1, &out));
}

static ntc_err try_inner(int fail) { return fail ? NTC_ERR_IO : NTC_OK; }
static ntc_err try_outer(int fail) { TRY(try_inner(fail)); return NTC_OK; }

TEST(err, try_macro_propagates) {
    ASSERT_EQ_INT(NTC_OK, try_outer(0));
    ASSERT_EQ_INT(NTC_ERR_IO, try_outer(1));
}
#endif /* UNIT_TEST */
