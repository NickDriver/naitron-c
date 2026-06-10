/* gzip.h - gzip (RFC 1952) response compression, backed by vendored miniz.
 *
 * Wraps miniz's raw DEFLATE with a gzip header + CRC32 + ISIZE trailer so a
 * browser's Accept-Encoding: gzip can be honored. Atomic responses only. */
#ifndef NTC_GZIP_H
#define NTC_GZIP_H

#include <stddef.h>
#include <stdint.h>

/* Compress src into a newly malloc'd gzip blob; sets *outlen. Returns NULL on
 * failure (or if compression did not help). Caller frees. */
uint8_t *ntc_gzip(const void *src, size_t srclen, size_t *outlen);

#endif /* NTC_GZIP_H */
