/* json.h - a small arena-based JSON parser + string escaper.
 *
 * Used by the built-in MCP server (P7) and available to controllers. Parsed
 * values point into arena memory; the source buffer may be reused after. */
#ifndef NTC_JSON_H
#define NTC_JSON_H

#include <stdbool.h>
#include <stddef.h>

#include "ntc/arena.h"
#include "ntc/slice.h"

typedef enum ntc_json_type {
    NTC_JSON_NULL, NTC_JSON_BOOL, NTC_JSON_NUM,
    NTC_JSON_STR, NTC_JSON_ARR, NTC_JSON_OBJ
} ntc_json_type;

typedef struct ntc_json ntc_json;
struct ntc_json {
    ntc_json_type type;
    bool b;
    double num;
    ntc_slice str;        /* STR: unescaped value (in arena) */
    ntc_json **items;     /* ARR */
    ntc_slice *keys;      /* OBJ */
    ntc_json **vals;      /* OBJ */
    size_t count;         /* ARR / OBJ length */
};

/* Parse buf[0..len). Returns NULL on malformed input. */
ntc_json *ntc_json_parse(ntc_arena *a, const char *buf, size_t len);

const ntc_json *ntc_json_get(const ntc_json *obj, const char *key);
ntc_slice ntc_json_str(const ntc_json *v);
double ntc_json_num(const ntc_json *v);

/* Escape src into dst as a JSON string body (no surrounding quotes),
 * NUL-terminated. Returns bytes written (excl NUL) or -1 if dst is too small. */
int ntc_json_escape(char *dst, size_t cap, ntc_slice src);

/* Serialize a parsed node back to compact JSON in dst (NUL-terminated).
 * Returns bytes written (excl NUL), or -1 if dst is too small. */
int ntc_json_emit(const ntc_json *v, char *dst, size_t cap);

#endif /* NTC_JSON_H */
