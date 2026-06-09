#include "ntc/crypto.h"

#include <string.h>

/* ---- SHA-256 (FIPS 180-4) ---- */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct { uint32_t h[8]; uint64_t total; uint8_t buf[64]; size_t n; } sha_ctx;

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha_init(sha_ctx *c) {
    static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->n = 0;
}

static void sha_block(sha_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
               (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha_update(sha_ctx *c, const uint8_t *p, size_t len) {
    c->total += len;
    while (len) {
        size_t take = 64 - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 64) { sha_block(c, c->buf); c->n = 0; }
    }
}

static void sha_final(sha_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->n != 56) sha_update(c, &zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->h[i];
    }
}

void ntc_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha_ctx c; sha_init(&c); sha_update(&c, data, len); sha_final(&c, out);
}

void ntc_hmac_sha256(const uint8_t *key, size_t keylen,
                     const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    uint8_t k[64];
    memset(k, 0, sizeof k);
    if (keylen > 64) ntc_sha256(key, keylen, k);
    else memcpy(k, key, keylen);

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    uint8_t inner[32];
    sha_ctx c;
    sha_init(&c); sha_update(&c, ipad, 64); sha_update(&c, msg, msglen); sha_final(&c, inner);
    sha_init(&c); sha_update(&c, opad, 64); sha_update(&c, inner, 32); sha_final(&c, out);
}

/* ---- base64url (no padding) ---- */
static const char B64U[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int ntc_base64url_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)in[i] << 16;
        int rem = (int)(len - i);
        if (rem > 1) n |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) n |= in[i + 2];
        int chars = rem >= 3 ? 4 : rem + 1;
        for (int j = 0; j < chars; j++) {
            if (o + 1 >= cap) return -1;
            out[o++] = B64U[(n >> (18 - 6 * j)) & 0x3f];
        }
    }
    if (o >= cap) return -1;
    out[o] = '\0';
    return (int)o;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int ntc_base64url_decode(const char *in, size_t len, uint8_t *out, size_t cap) {
    size_t o = 0;
    uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < len; i++) {
        int v = b64val(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    return (int)o;
}

bool ntc_ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

#ifdef UNIT_TEST
#include "ntc/test.h"
#include "ntc/slice.h"
#include <stdio.h>

static void hexstr(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", b[i]);
}

TEST(crypto, sha256_vectors) {
    uint8_t d[32]; char h[65];
    ntc_sha256((const uint8_t *)"abc", 3, d); hexstr(d, 32, h);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(h),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    ntc_sha256((const uint8_t *)"", 0, d); hexstr(d, 32, h);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(h),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST(crypto, hmac_sha256_rfc4231) {
    uint8_t mac[32]; char h[65];
    /* RFC 4231 test case 2 */
    ntc_hmac_sha256((const uint8_t *)"Jefe", 4,
                    (const uint8_t *)"what do ya want for nothing?", 28, mac);
    hexstr(mac, 32, h);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(h),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

TEST(crypto, base64url_roundtrip) {
    char enc[64]; uint8_t dec[64];
    const char *msg = "hello world!";
    int n = ntc_base64url_encode((const uint8_t *)msg, strlen(msg), enc, sizeof enc);
    ASSERT_TRUE(n > 0);
    int m = ntc_base64url_decode(enc, (size_t)n, dec, sizeof dec);
    ASSERT_EQ_INT((int)strlen(msg), m);
    ASSERT_EQ_INT(0, memcmp(dec, msg, strlen(msg)));
    /* no padding, url-safe alphabet */
    ASSERT_TRUE(strchr(enc, '=') == NULL);
}

TEST(crypto, ct_eq) {
    uint8_t a[4] = { 1, 2, 3, 4 }, b[4] = { 1, 2, 3, 4 }, c[4] = { 1, 2, 3, 5 };
    ASSERT_TRUE(ntc_ct_eq(a, b, 4));
    ASSERT_FALSE(ntc_ct_eq(a, c, 4));
}
#endif /* UNIT_TEST */
