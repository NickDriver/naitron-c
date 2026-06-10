#define _GNU_SOURCE
#include "ntc/gzip.h"

#include "miniz.h"

#include <stdlib.h>
#include <string.h>

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

uint8_t *ntc_gzip(const void *src, size_t srclen, size_t *outlen) {
    if (!src || srclen == 0 || !outlen) return NULL;

    /* raw DEFLATE (negative window_bits = no zlib header), default level */
    unsigned flags = (unsigned)tdefl_create_comp_flags_from_zip_params(6, -15, MZ_DEFAULT_STRATEGY);
    size_t dlen = 0;
    void *deflated = tdefl_compress_mem_to_heap(src, srclen, &dlen, flags);
    if (!deflated) return NULL;

    size_t total = 10 + dlen + 8; /* gzip header + deflate + CRC32 + ISIZE */
    if (total >= srclen) { mz_free(deflated); return NULL; } /* didn't help */

    uint8_t *out = malloc(total);
    if (!out) { mz_free(deflated); return NULL; }

    /* gzip header: magic, CM=deflate, no flags, no mtime, XFL=0, OS=unknown */
    static const uint8_t hdr[10] = { 0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff };
    memcpy(out, hdr, 10);
    memcpy(out + 10, deflated, dlen);
    mz_free(deflated);

    uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, src, srclen);
    put_le32(out + 10 + dlen, crc);
    put_le32(out + 10 + dlen + 4, (uint32_t)(srclen & 0xFFFFFFFFu)); /* ISIZE mod 2^32 */

    *outlen = total;
    return out;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(gzip, roundtrip) {
    /* a compressible buffer */
    char src[4096];
    for (size_t i = 0; i < sizeof src; i++) src[i] = (char)('a' + (i % 16));

    size_t gzlen = 0;
    uint8_t *gz = ntc_gzip(src, sizeof src, &gzlen);
    ASSERT_NOT_NULL(gz);
    ASSERT_TRUE(gzlen < sizeof src);          /* it actually compressed */
    ASSERT_EQ_INT(0x1f, gz[0]);               /* gzip magic */
    ASSERT_EQ_INT(0x8b, gz[1]);
    ASSERT_EQ_INT(0x08, gz[2]);               /* CM = deflate */

    /* ISIZE trailer == original length */
    uint32_t isize = (uint32_t)gz[gzlen - 4] | ((uint32_t)gz[gzlen - 3] << 8) |
                     ((uint32_t)gz[gzlen - 2] << 16) | ((uint32_t)gz[gzlen - 1] << 24);
    ASSERT_EQ_UINT((unsigned)sizeof src, (unsigned)isize);

    /* inflate the raw DEFLATE body (between the 10-byte header and 8-byte trailer) */
    size_t out_len = 0;
    void *inflated = tinfl_decompress_mem_to_heap(gz + 10, gzlen - 18, &out_len, 0);
    ASSERT_NOT_NULL(inflated);
    ASSERT_EQ_UINT((unsigned)sizeof src, (unsigned)out_len);
    ASSERT_TRUE(memcmp(inflated, src, sizeof src) == 0);
    mz_free(inflated);
    free(gz);
}

TEST(gzip, incompressible_returns_null) {
    /* tiny / random-ish input where gzip overhead would not pay off */
    const char *s = "x";
    size_t n = 0;
    ASSERT_TRUE(ntc_gzip(s, 1, &n) == NULL);
}
#endif /* UNIT_TEST */
