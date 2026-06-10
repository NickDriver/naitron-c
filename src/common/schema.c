#define _GNU_SOURCE
#include "ntc/schema.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static void fail(char *err, size_t cap, const char *msg) {
    if (err && cap) snprintf(err, cap, "%s", msg);
}

/* true if the instance node satisfies a "type" name */
static bool type_ok(const char *t, const ntc_json *v) {
    if (strcmp(t, "object") == 0) return v->type == NTC_JSON_OBJ;
    if (strcmp(t, "array") == 0) return v->type == NTC_JSON_ARR;
    if (strcmp(t, "string") == 0) return v->type == NTC_JSON_STR;
    if (strcmp(t, "boolean") == 0) return v->type == NTC_JSON_BOOL;
    if (strcmp(t, "null") == 0) return v->type == NTC_JSON_NULL;
    if (strcmp(t, "number") == 0) return v->type == NTC_JSON_NUM;
    if (strcmp(t, "integer") == 0)
        return v->type == NTC_JSON_NUM && v->num == floor(v->num);
    return true; /* unknown type name: don't reject */
}

/* deep-ish equality for enum matching (covers scalars + shallow compares) */
static bool json_eq(const ntc_json *a, const ntc_json *b) {
    if (a->type != b->type) return false;
    switch (a->type) {
        case NTC_JSON_NULL: return true;
        case NTC_JSON_BOOL: return a->b == b->b;
        case NTC_JSON_NUM:  return a->num == b->num;
        case NTC_JSON_STR:  return a->str.len == b->str.len &&
                                   memcmp(a->str.ptr, b->str.ptr, a->str.len) == 0;
        default: return false;
    }
}

bool ntc_schema_validate(const ntc_json *schema, const ntc_json *instance,
                         char *err, size_t errcap) {
    if (!schema || schema->type != NTC_JSON_OBJ) return true; /* no/blank schema: accept */
    if (!instance) { fail(err, errcap, "missing value"); return false; }

    /* type */
    const ntc_json *t = ntc_json_get(schema, "type");
    if (t && t->type == NTC_JSON_STR) {
        char tn[24];
        snprintf(tn, sizeof tn, "%.*s", (int)t->str.len, t->str.ptr);
        if (!type_ok(tn, instance)) {
            char m[64]; snprintf(m, sizeof m, "expected type %s", tn);
            fail(err, errcap, m);
            return false;
        }
    }

    /* enum */
    const ntc_json *en = ntc_json_get(schema, "enum");
    if (en && en->type == NTC_JSON_ARR) {
        bool found = false;
        for (size_t i = 0; i < en->count; i++) if (json_eq(en->items[i], instance)) { found = true; break; }
        if (!found) { fail(err, errcap, "value not in enum"); return false; }
    }

    /* numbers */
    if (instance->type == NTC_JSON_NUM) {
        const ntc_json *mn = ntc_json_get(schema, "minimum");
        const ntc_json *mx = ntc_json_get(schema, "maximum");
        if (mn && mn->type == NTC_JSON_NUM && instance->num < mn->num) { fail(err, errcap, "below minimum"); return false; }
        if (mx && mx->type == NTC_JSON_NUM && instance->num > mx->num) { fail(err, errcap, "above maximum"); return false; }
    }

    /* strings */
    if (instance->type == NTC_JSON_STR) {
        const ntc_json *mn = ntc_json_get(schema, "minLength");
        const ntc_json *mx = ntc_json_get(schema, "maxLength");
        if (mn && mn->type == NTC_JSON_NUM && instance->str.len < (size_t)mn->num) { fail(err, errcap, "string too short"); return false; }
        if (mx && mx->type == NTC_JSON_NUM && instance->str.len > (size_t)mx->num) { fail(err, errcap, "string too long"); return false; }
    }

    /* arrays */
    if (instance->type == NTC_JSON_ARR) {
        const ntc_json *mn = ntc_json_get(schema, "minItems");
        const ntc_json *mx = ntc_json_get(schema, "maxItems");
        if (mn && mn->type == NTC_JSON_NUM && instance->count < (size_t)mn->num) { fail(err, errcap, "too few items"); return false; }
        if (mx && mx->type == NTC_JSON_NUM && instance->count > (size_t)mx->num) { fail(err, errcap, "too many items"); return false; }
        const ntc_json *items = ntc_json_get(schema, "items");
        if (items && items->type == NTC_JSON_OBJ)
            for (size_t i = 0; i < instance->count; i++)
                if (!ntc_schema_validate(items, instance->items[i], err, errcap)) return false;
    }

    /* objects: required, properties, additionalProperties */
    if (instance->type == NTC_JSON_OBJ) {
        const ntc_json *req = ntc_json_get(schema, "required");
        if (req && req->type == NTC_JSON_ARR) {
            for (size_t i = 0; i < req->count; i++) {
                const ntc_json *name = req->items[i];
                if (name->type != NTC_JSON_STR) continue;
                char key[96];
                snprintf(key, sizeof key, "%.*s", (int)name->str.len, name->str.ptr);
                if (!ntc_json_get(instance, key)) {
                    char m[128]; snprintf(m, sizeof m, "missing required property '%s'", key);
                    fail(err, errcap, m);
                    return false;
                }
            }
        }
        const ntc_json *props = ntc_json_get(schema, "properties");
        if (props && props->type == NTC_JSON_OBJ) {
            for (size_t i = 0; i < props->count; i++) {
                char key[96];
                snprintf(key, sizeof key, "%.*s", (int)props->keys[i].len, props->keys[i].ptr);
                const ntc_json *iv = ntc_json_get(instance, key);
                if (iv && !ntc_schema_validate(props->vals[i], iv, err, errcap)) return false;
            }
        }
        const ntc_json *ap = ntc_json_get(schema, "additionalProperties");
        if (ap && ap->type == NTC_JSON_BOOL && !ap->b && props && props->type == NTC_JSON_OBJ) {
            for (size_t i = 0; i < instance->count; i++) {
                char key[96];
                snprintf(key, sizeof key, "%.*s", (int)instance->keys[i].len, instance->keys[i].ptr);
                if (!ntc_json_get(props, key)) {
                    char m[128]; snprintf(m, sizeof m, "unexpected property '%s'", key);
                    fail(err, errcap, m);
                    return false;
                }
            }
        }
    }

    return true;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

static bool check(const char *schema_s, const char *inst_s, char *err, size_t errcap) {
    ntc_arena a;
    ntc_arena_init(&a, 8192);
    ntc_json *sc = ntc_json_parse(&a, schema_s, strlen(schema_s));
    ntc_json *in = ntc_json_parse(&a, inst_s, strlen(inst_s));
    bool ok = ntc_schema_validate(sc, in, err, errcap);
    ntc_arena_destroy(&a);
    return ok;
}

TEST(schema, type_and_required) {
    char err[128];
    const char *s = "{\"type\":\"object\",\"required\":[\"name\",\"age\"],"
                    "\"properties\":{\"name\":{\"type\":\"string\"},\"age\":{\"type\":\"integer\"}}}";
    ASSERT_TRUE(check(s, "{\"name\":\"bob\",\"age\":30}", err, sizeof err));
    ASSERT_FALSE(check(s, "{\"name\":\"bob\"}", err, sizeof err)); /* missing age */
    ASSERT_TRUE(strstr(err, "age") != NULL);
    ASSERT_FALSE(check(s, "{\"name\":123,\"age\":30}", err, sizeof err)); /* name wrong type */
    ASSERT_FALSE(check(s, "{\"name\":\"bob\",\"age\":1.5}", err, sizeof err)); /* not integer */
}

TEST(schema, constraints) {
    char err[128];
    ASSERT_TRUE(check("{\"type\":\"string\",\"minLength\":2,\"maxLength\":5}", "\"abc\"", err, sizeof err));
    ASSERT_FALSE(check("{\"type\":\"string\",\"minLength\":2}", "\"a\"", err, sizeof err));
    ASSERT_TRUE(check("{\"type\":\"number\",\"minimum\":0,\"maximum\":10}", "5", err, sizeof err));
    ASSERT_FALSE(check("{\"type\":\"number\",\"maximum\":10}", "11", err, sizeof err));
    ASSERT_TRUE(check("{\"enum\":[\"a\",\"b\"]}", "\"b\"", err, sizeof err));
    ASSERT_FALSE(check("{\"enum\":[\"a\",\"b\"]}", "\"c\"", err, sizeof err));
}

TEST(schema, arrays_and_additional_props) {
    char err[128];
    const char *arr = "{\"type\":\"array\",\"minItems\":1,\"items\":{\"type\":\"integer\"}}";
    ASSERT_TRUE(check(arr, "[1,2,3]", err, sizeof err));
    ASSERT_FALSE(check(arr, "[]", err, sizeof err));      /* minItems */
    ASSERT_FALSE(check(arr, "[1,\"x\"]", err, sizeof err)); /* item type */

    const char *strict = "{\"type\":\"object\",\"additionalProperties\":false,"
                         "\"properties\":{\"a\":{\"type\":\"string\"}}}";
    ASSERT_TRUE(check(strict, "{\"a\":\"x\"}", err, sizeof err));
    ASSERT_FALSE(check(strict, "{\"a\":\"x\",\"b\":1}", err, sizeof err)); /* extra prop */
    ASSERT_TRUE(strstr(err, "unexpected") != NULL);
}

TEST(schema, blank_schema_accepts) {
    char err[128];
    ASSERT_TRUE(check("{}", "{\"anything\":true}", err, sizeof err));
}
#endif /* UNIT_TEST */
