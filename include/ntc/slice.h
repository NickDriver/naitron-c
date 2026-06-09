/* slice.h - length-delimited string view (ptr + len), not null-terminated.
 *
 * Enables zero-copy parsing and kills a class of overflow bugs vs char*. */
#ifndef NTC_SLICE_H
#define NTC_SLICE_H

#include <stddef.h>
#include <stdbool.h>

typedef struct ntc_slice {
    const char *ptr;
    size_t len;
} ntc_slice;

/* Compile-time slice from a string literal (no strlen at runtime). */
#define NTC_SLICE_LIT(s) ((ntc_slice){ (s), sizeof(s) - 1 })

ntc_slice ntc_slice_cstr(const char *s);
ntc_slice ntc_slice_new(const char *p, size_t n);
bool ntc_slice_eq(ntc_slice a, ntc_slice b);
bool ntc_slice_eq_cstr(ntc_slice a, const char *s);
bool ntc_slice_starts_with(ntc_slice a, ntc_slice prefix);
ntc_slice ntc_slice_trim(ntc_slice s); /* trim ASCII whitespace both ends */

#endif /* NTC_SLICE_H */
