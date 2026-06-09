#include "ntc/arena.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NTC_ARENA_ALIGN 16u

struct ntc_arena_block {
    ntc_arena_block *next;
    size_t cap;  /* usable bytes in data[]            */
    size_t off;  /* bytes consumed from data[] so far */
    size_t _pad; /* keep data[] 16-byte aligned       */
    unsigned char data[];
};

static ntc_arena_block *block_new(size_t cap) {
    if (cap > SIZE_MAX - sizeof(ntc_arena_block)) return NULL; /* size overflow */
    ntc_arena_block *b = malloc(sizeof(*b) + cap);
    if (!b) return NULL;
    b->next = NULL;
    b->cap = cap;
    b->off = 0;
    b->_pad = 0;
    return b;
}

static uintptr_t align_up(uintptr_t n, uintptr_t a) {
    return (n + (a - 1)) & ~(a - 1);
}

ntc_err ntc_arena_init(ntc_arena *a, size_t block_size) {
    if (!a) return NTC_ERR_INVALID;
    if (block_size == 0) block_size = NTC_ARENA_DEFAULT_BLOCK;
    ntc_arena_block *b = block_new(block_size);
    if (!b) return NTC_ERR_OOM;
    a->first = b;
    a->cur = b;
    a->block_size = block_size;
    return NTC_OK;
}

void *ntc_arena_alloc(ntc_arena *a, size_t size) {
    if (!a || !a->cur) return NULL;
    if (size == 0) size = 1;
    if (size > SIZE_MAX - (NTC_ARENA_ALIGN - 1)) return NULL; /* size overflow */

    ntc_arena_block *b = a->cur;
    uintptr_t base = (uintptr_t)b->data;
    uintptr_t aligned = align_up(base + b->off, NTC_ARENA_ALIGN);
    size_t new_off = (size_t)(aligned - base);

    if (new_off > b->cap || size > b->cap - new_off) {
        /* Doesn't fit: grow with a block big enough to hold it after alignment. */
        size_t cap = a->block_size;
        size_t need = size + (NTC_ARENA_ALIGN - 1);
        if (need > cap) cap = need;
        ntc_arena_block *nb = block_new(cap);
        if (!nb) return NULL;
        b->next = nb;
        a->cur = nb;
        b = nb;
        base = (uintptr_t)b->data;
        aligned = align_up(base, NTC_ARENA_ALIGN);
        new_off = (size_t)(aligned - base);
    }

    b->off = new_off + size;
    return (void *)aligned;
}

void *ntc_arena_calloc(ntc_arena *a, size_t size) {
    void *p = ntc_arena_alloc(a, size);
    if (p) memset(p, 0, size == 0 ? 1 : size);
    return p;
}

void ntc_arena_reset(ntc_arena *a) {
    if (!a || !a->first) return;
    ntc_arena_block *b = a->first->next;
    while (b) {
        ntc_arena_block *next = b->next;
        free(b);
        b = next;
    }
    a->first->next = NULL;
    a->first->off = 0;
    a->cur = a->first;
}

void ntc_arena_destroy(ntc_arena *a) {
    if (!a) return;
    ntc_arena_block *b = a->first;
    while (b) {
        ntc_arena_block *next = b->next;
        free(b);
        b = next;
    }
    a->first = NULL;
    a->cur = NULL;
    a->block_size = 0;
}

size_t ntc_arena_used(const ntc_arena *a) {
    size_t total = 0;
    for (const ntc_arena_block *b = a ? a->first : NULL; b; b = b->next)
        total += b->off;
    return total;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(arena, init_and_alloc) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 256));
    void *p = ntc_arena_alloc(&a, 16);
    ASSERT_NOT_NULL(p);
    ntc_arena_destroy(&a);
}

TEST(arena, allocations_are_16_byte_aligned) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 1024));
    ASSERT_NOT_NULL(ntc_arena_alloc(&a, 1));
    void *q = ntc_arena_alloc(&a, 7);
    void *r = ntc_arena_alloc(&a, 33);
    ASSERT_EQ_UINT(0u, (uintptr_t)q % NTC_ARENA_ALIGN);
    ASSERT_EQ_UINT(0u, (uintptr_t)r % NTC_ARENA_ALIGN);
    ntc_arena_destroy(&a);
}

TEST(arena, grows_to_new_block) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 64));
    void *p1 = ntc_arena_alloc(&a, 40);
    void *p2 = ntc_arena_alloc(&a, 40); /* won't fit in 64 -> new block */
    ASSERT_NOT_NULL(p1);
    ASSERT_NOT_NULL(p2);
    ASSERT_TRUE(p1 != p2);
    ntc_arena_destroy(&a);
}

TEST(arena, alloc_larger_than_block) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 64));
    unsigned char *p = ntc_arena_alloc(&a, 4096);
    ASSERT_NOT_NULL(p);
    memset(p, 0xAB, 4096); /* let ASan validate the full extent */
    ASSERT_EQ_INT(0xAB, p[4095]);
    ntc_arena_destroy(&a);
}

TEST(arena, calloc_is_zeroed) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 128));
    unsigned char *p = ntc_arena_calloc(&a, 64);
    ASSERT_NOT_NULL(p);
    int nonzero = 0;
    for (int i = 0; i < 64; i++) nonzero |= p[i];
    ASSERT_EQ_INT(0, nonzero);
    ntc_arena_destroy(&a);
}

TEST(arena, reset_rewinds) {
    ntc_arena a;
    ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 128));
    ntc_arena_alloc(&a, 64);
    ntc_arena_alloc(&a, 300); /* spills into a second block */
    ASSERT_TRUE(ntc_arena_used(&a) > 0);
    ntc_arena_reset(&a);
    ASSERT_EQ_UINT(0u, ntc_arena_used(&a));
    ASSERT_NOT_NULL(ntc_arena_alloc(&a, 32));
    ntc_arena_destroy(&a);
}
#endif /* UNIT_TEST */
