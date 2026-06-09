#include "ntc/slice.h"

#include <string.h>

ntc_slice ntc_slice_cstr(const char *s) {
    return (ntc_slice){ s, s ? strlen(s) : 0 };
}

ntc_slice ntc_slice_new(const char *p, size_t n) {
    return (ntc_slice){ p, n };
}

bool ntc_slice_eq(ntc_slice a, ntc_slice b) {
    if (a.len != b.len) return false;
    if (a.len == 0) return true;
    return memcmp(a.ptr, b.ptr, a.len) == 0;
}

bool ntc_slice_eq_cstr(ntc_slice a, const char *s) {
    return ntc_slice_eq(a, ntc_slice_cstr(s));
}

bool ntc_slice_starts_with(ntc_slice a, ntc_slice prefix) {
    if (prefix.len > a.len) return false;
    if (prefix.len == 0) return true;
    return memcmp(a.ptr, prefix.ptr, prefix.len) == 0;
}

static bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

ntc_slice ntc_slice_trim(ntc_slice s) {
    size_t start = 0, end = s.len;
    while (start < end && is_space(s.ptr[start])) start++;
    while (end > start && is_space(s.ptr[end - 1])) end--;
    return ntc_slice_new(s.ptr + start, end - start);
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(slice, eq) {
    ASSERT_TRUE(ntc_slice_eq(NTC_SLICE_LIT("abc"), ntc_slice_cstr("abc")));
    ASSERT_FALSE(ntc_slice_eq(NTC_SLICE_LIT("abc"), ntc_slice_cstr("abd")));
    ASSERT_FALSE(ntc_slice_eq(NTC_SLICE_LIT("ab"), ntc_slice_cstr("abc")));
}

TEST(slice, cstr_length_and_eq_cstr) {
    ntc_slice s = ntc_slice_cstr("hello");
    ASSERT_EQ_UINT(5u, s.len);
    ASSERT_TRUE(ntc_slice_eq_cstr(s, "hello"));
    ASSERT_FALSE(ntc_slice_eq_cstr(s, "help"));
}

TEST(slice, starts_with) {
    ASSERT_TRUE(ntc_slice_starts_with(NTC_SLICE_LIT("/api/users"), NTC_SLICE_LIT("/api/")));
    ASSERT_FALSE(ntc_slice_starts_with(NTC_SLICE_LIT("/x"), NTC_SLICE_LIT("/api/")));
    ASSERT_TRUE(ntc_slice_starts_with(NTC_SLICE_LIT("anything"), NTC_SLICE_LIT("")));
}

TEST(slice, trim) {
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_trim(NTC_SLICE_LIT("  \t hi \n")), "hi"));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_trim(NTC_SLICE_LIT("nospace")), "nospace"));
    ASSERT_EQ_UINT(0u, ntc_slice_trim(NTC_SLICE_LIT("   ")).len);
}

TEST(slice, empty) {
    ASSERT_TRUE(ntc_slice_eq(NTC_SLICE_LIT(""), ntc_slice_cstr("")));
    ASSERT_TRUE(ntc_slice_eq(NTC_SLICE_LIT(""), ntc_slice_new(NULL, 0)));
}

/* Planned for P2 (HTTP parser): ntc_slice_split / ntc_slice_find_char. */
TEST_TODO(slice, split_on_char) { }
#endif /* UNIT_TEST */
