#include "ntc/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NTC_JSON_MAX_MEMBERS 64
#define NTC_JSON_MAX_DEPTH   32

typedef struct { const char *p, *end; ntc_arena *a; bool err; int depth; } P;

static void skip_ws(P *s) {
    while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r'))
        s->p++;
}

static ntc_json *new_val(P *s, ntc_json_type t) {
    ntc_json *v = ntc_arena_calloc(s->a, sizeof *v);
    if (!v) { s->err = true; return NULL; }
    v->type = t;
    return v;
}

static ntc_slice parse_string(P *s) {
    s->p++; /* opening quote */
    char *buf = ntc_arena_alloc(s->a, (size_t)(s->end - s->p) + 1);
    if (!buf) { s->err = true; return ntc_slice_new(NULL, 0); }
    size_t o = 0;
    while (s->p < s->end && *s->p != '"') {
        char c = *s->p++;
        if (c != '\\') { buf[o++] = c; continue; }
        if (s->p >= s->end) { s->err = true; break; }
        char e = *s->p++;
        switch (e) {
            case '"': buf[o++] = '"'; break;
            case '\\': buf[o++] = '\\'; break;
            case '/': buf[o++] = '/'; break;
            case 'b': buf[o++] = '\b'; break;
            case 'f': buf[o++] = '\f'; break;
            case 'n': buf[o++] = '\n'; break;
            case 'r': buf[o++] = '\r'; break;
            case 't': buf[o++] = '\t'; break;
            case 'u': {
                if (s->end - s->p < 4) { s->err = true; break; }
                unsigned cp = 0;
                for (int i = 0; i < 4; i++) {
                    char h = *s->p++;
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                    else { s->err = true; break; }
                }
                if (cp < 0x80) buf[o++] = (char)cp;
                else if (cp < 0x800) { buf[o++] = (char)(0xC0 | (cp >> 6)); buf[o++] = (char)(0x80 | (cp & 0x3F)); }
                else { buf[o++] = (char)(0xE0 | (cp >> 12)); buf[o++] = (char)(0x80 | ((cp >> 6) & 0x3F)); buf[o++] = (char)(0x80 | (cp & 0x3F)); }
                break;
            }
            default: s->err = true; break;
        }
    }
    if (s->p < s->end && *s->p == '"') s->p++; else s->err = true;
    return ntc_slice_new(buf, o);
}

static ntc_json *parse_value(P *s) {
    if (s->err) return NULL;
    if (++s->depth > NTC_JSON_MAX_DEPTH) { s->err = true; s->depth--; return NULL; }
    skip_ws(s);
    if (s->p >= s->end) { s->err = true; s->depth--; return NULL; }

    ntc_json *v = NULL;
    char c = *s->p;
    if (c == '{') {
        s->p++;
        v = new_val(s, NTC_JSON_OBJ);
        ntc_slice keys[NTC_JSON_MAX_MEMBERS];
        ntc_json *vals[NTC_JSON_MAX_MEMBERS];
        size_t n = 0;
        skip_ws(s);
        if (s->p < s->end && *s->p == '}') { s->p++; }
        else for (;;) {
            skip_ws(s);
            if (s->p >= s->end || *s->p != '"') { s->err = true; break; }
            ntc_slice k = parse_string(s);
            skip_ws(s);
            if (s->p >= s->end || *s->p != ':') { s->err = true; break; }
            s->p++;
            ntc_json *val = parse_value(s);
            if (s->err) break;
            if (n < NTC_JSON_MAX_MEMBERS) { keys[n] = k; vals[n] = val; n++; }
            skip_ws(s);
            if (s->p < s->end && *s->p == ',') { s->p++; continue; }
            if (s->p < s->end && *s->p == '}') { s->p++; break; }
            s->err = true; break;
        }
        if (v && !s->err) {
            v->count = n;
            v->keys = ntc_arena_alloc(s->a, (n ? n : 1) * sizeof(ntc_slice));
            v->vals = ntc_arena_alloc(s->a, (n ? n : 1) * sizeof(ntc_json *));
            if (!v->keys || !v->vals) s->err = true;
            else for (size_t i = 0; i < n; i++) { v->keys[i] = keys[i]; v->vals[i] = vals[i]; }
        }
    } else if (c == '[') {
        s->p++;
        v = new_val(s, NTC_JSON_ARR);
        ntc_json *items[NTC_JSON_MAX_MEMBERS];
        size_t n = 0;
        skip_ws(s);
        if (s->p < s->end && *s->p == ']') { s->p++; }
        else for (;;) {
            ntc_json *it = parse_value(s);
            if (s->err) break;
            if (n < NTC_JSON_MAX_MEMBERS) items[n++] = it;
            skip_ws(s);
            if (s->p < s->end && *s->p == ',') { s->p++; continue; }
            if (s->p < s->end && *s->p == ']') { s->p++; break; }
            s->err = true; break;
        }
        if (v && !s->err) {
            v->count = n;
            v->items = ntc_arena_alloc(s->a, (n ? n : 1) * sizeof(ntc_json *));
            if (!v->items) s->err = true;
            else for (size_t i = 0; i < n; i++) v->items[i] = items[i];
        }
    } else if (c == '"') {
        v = new_val(s, NTC_JSON_STR);
        if (v) v->str = parse_string(s);
    } else if (c == 't') {
        if (s->end - s->p >= 4 && memcmp(s->p, "true", 4) == 0) { s->p += 4; v = new_val(s, NTC_JSON_BOOL); if (v) v->b = true; }
        else s->err = true;
    } else if (c == 'f') {
        if (s->end - s->p >= 5 && memcmp(s->p, "false", 5) == 0) { s->p += 5; v = new_val(s, NTC_JSON_BOOL); if (v) v->b = false; }
        else s->err = true;
    } else if (c == 'n') {
        if (s->end - s->p >= 4 && memcmp(s->p, "null", 4) == 0) { s->p += 4; v = new_val(s, NTC_JSON_NULL); }
        else s->err = true;
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        const char *st = s->p;
        while (s->p < s->end && (*s->p == '-' || *s->p == '+' || *s->p == '.' ||
               *s->p == 'e' || *s->p == 'E' || (*s->p >= '0' && *s->p <= '9'))) s->p++;
        char tmp[64];
        size_t len = (size_t)(s->p - st);
        if (len >= sizeof tmp) len = sizeof tmp - 1;
        memcpy(tmp, st, len);
        tmp[len] = '\0';
        v = new_val(s, NTC_JSON_NUM);
        if (v) v->num = strtod(tmp, NULL);
    } else {
        s->err = true;
    }
    s->depth--;
    return s->err ? NULL : v;
}

ntc_json *ntc_json_parse(ntc_arena *a, const char *buf, size_t len) {
    if (!a || !buf) return NULL;
    P s = { buf, buf + len, a, false, 0 };
    ntc_json *v = parse_value(&s);
    return s.err ? NULL : v;
}

const ntc_json *ntc_json_get(const ntc_json *o, const char *key) {
    if (!o || o->type != NTC_JSON_OBJ) return NULL;
    ntc_slice k = ntc_slice_cstr(key);
    for (size_t i = 0; i < o->count; i++)
        if (ntc_slice_eq(o->keys[i], k)) return o->vals[i];
    return NULL;
}

ntc_slice ntc_json_str(const ntc_json *v) {
    return (v && v->type == NTC_JSON_STR) ? v->str : ntc_slice_new(NULL, 0);
}

double ntc_json_num(const ntc_json *v) {
    return (v && v->type == NTC_JSON_NUM) ? v->num : 0.0;
}

int ntc_json_escape(char *dst, size_t cap, ntc_slice src) {
    size_t o = 0;
#define PUT(ch) do { if (o + 1 >= cap) return -1; dst[o++] = (char)(ch); } while (0)
    for (size_t i = 0; i < src.len; i++) {
        unsigned char c = (unsigned char)src.ptr[i];
        switch (c) {
            case '"':  PUT('\\'); PUT('"'); break;
            case '\\': PUT('\\'); PUT('\\'); break;
            case '\n': PUT('\\'); PUT('n'); break;
            case '\r': PUT('\\'); PUT('r'); break;
            case '\t': PUT('\\'); PUT('t'); break;
            case '\b': PUT('\\'); PUT('b'); break;
            case '\f': PUT('\\'); PUT('f'); break;
            default:
                if (c < 0x20) {
                    char tmp[8];
                    int m = snprintf(tmp, sizeof tmp, "\\u%04x", c);
                    for (int k = 0; k < m; k++) PUT(tmp[k]);
                } else PUT(c);
        }
    }
    if (o >= cap) return -1;
    dst[o] = '\0';
#undef PUT
    return (int)o;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(json, parse_object) {
    ntc_arena a; ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 4096));
    const char *j = "{\"method\":\"tools/call\",\"id\":7,\"ok\":true}";
    ntc_json *v = ntc_json_parse(&a, j, strlen(j));
    ASSERT_NOT_NULL(v);
    ASSERT_EQ_INT(NTC_JSON_OBJ, v->type);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(v, "method")), "tools/call"));
    ASSERT_EQ_INT(7, (int)ntc_json_num(ntc_json_get(v, "id")));
    ASSERT_TRUE(ntc_json_get(v, "ok")->b);
    ntc_arena_destroy(&a);
}

TEST(json, nested_and_arrays) {
    ntc_arena a; ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 4096));
    const char *j = "{\"params\":{\"name\":\"x\",\"arguments\":{\"bin\":\"/b\"}},\"a\":[1,2,3]}";
    ntc_json *v = ntc_json_parse(&a, j, strlen(j));
    ASSERT_NOT_NULL(v);
    const ntc_json *p = ntc_json_get(v, "params");
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(p, "name")), "x"));
    const ntc_json *args = ntc_json_get(p, "arguments");
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(args, "bin")), "/b"));
    const ntc_json *arr = ntc_json_get(v, "a");
    ASSERT_EQ_INT(NTC_JSON_ARR, arr->type);
    ASSERT_EQ_UINT(3u, arr->count);
    ASSERT_EQ_INT(2, (int)ntc_json_num(arr->items[1]));
    ntc_arena_destroy(&a);
}

TEST(json, escapes_in_string) {
    ntc_arena a; ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 4096));
    const char *j = "{\"s\":\"a\\\"b\\n\\u0041\"}";
    ntc_json *v = ntc_json_parse(&a, j, strlen(j));
    ASSERT_NOT_NULL(v);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(v, "s")), "a\"b\nA"));
    ntc_arena_destroy(&a);
}

TEST(json, rejects_malformed) {
    ntc_arena a; ASSERT_EQ_INT(NTC_OK, ntc_arena_init(&a, 4096));
    ASSERT_NULL(ntc_json_parse(&a, "{\"a\":}", 6));
    ASSERT_NULL(ntc_json_parse(&a, "[1,2", 4));
    ntc_arena_destroy(&a);
}

TEST(json, escape_output) {
    char buf[64];
    int n = ntc_json_escape(buf, sizeof buf, NTC_SLICE_LIT("he\"llo\n"));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(buf), "he\\\"llo\\n"));
}
#endif /* UNIT_TEST */
