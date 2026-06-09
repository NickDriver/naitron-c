/* arena.h - per-request bump allocator.
 *
 * The framework's memory-safety cornerstone: allocate freely during a request,
 * then ntc_arena_reset()/destroy() frees everything in one shot. This deletes
 * the leak-on-error-path problem - on any error you just return.
 */
#ifndef NTC_ARENA_H
#define NTC_ARENA_H

#include <stddef.h>
#include "ntc/err.h"

typedef struct ntc_arena_block ntc_arena_block;

typedef struct ntc_arena {
    ntc_arena_block *first; /* head of block list (kept across reset) */
    ntc_arena_block *cur;   /* current block we bump from            */
    size_t block_size;      /* default size for new blocks           */
} ntc_arena;

#define NTC_ARENA_DEFAULT_BLOCK (16u * 1024u)

/* Initialize with a default block size (0 => NTC_ARENA_DEFAULT_BLOCK). */
ntc_err ntc_arena_init(ntc_arena *a, size_t block_size);

/* Allocate `size` bytes, 16-byte aligned. Returns NULL on OOM/overflow. */
void *ntc_arena_alloc(ntc_arena *a, size_t size);

/* Like ntc_arena_alloc but zero-initialized. */
void *ntc_arena_calloc(ntc_arena *a, size_t size);

/* Free everything but the first block and rewind it (cheap reuse). */
void ntc_arena_reset(ntc_arena *a);

/* Free all blocks. Safe to call on a zeroed/destroyed arena. */
void ntc_arena_destroy(ntc_arena *a);

/* Total bytes handed out (incl. alignment gaps); mainly for tests. */
size_t ntc_arena_used(const ntc_arena *a);

#endif /* NTC_ARENA_H */
