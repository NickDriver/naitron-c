#include "ntc/registry.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

struct ntc_registry { sqlite3 *db; };

static const char *SCHEMA =
    "PRAGMA foreign_keys=ON;"
    "CREATE TABLE IF NOT EXISTS services("
    "  id INTEGER PRIMARY KEY,"
    "  name TEXT UNIQUE NOT NULL,"
    "  bin TEXT NOT NULL,"
    "  enabled INTEGER NOT NULL DEFAULT 1);"
    "CREATE TABLE IF NOT EXISTS routes("
    "  id INTEGER PRIMARY KEY,"
    "  method TEXT NOT NULL,"
    "  pattern TEXT NOT NULL,"
    "  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,"
    "  UNIQUE(method, pattern));";

static ntc_err exec_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return NTC_ERR_INTERNAL;
    }
    return NTC_OK;
}

ntc_err ntc_registry_open(ntc_registry **out, const char *path) {
    if (!out || !path) return NTC_ERR_INVALID;
    ntc_registry *r = calloc(1, sizeof *r);
    if (!r) return NTC_ERR_OOM;
    if (sqlite3_open(path, &r->db) != SQLITE_OK) {
        sqlite3_close(r->db);
        free(r);
        return NTC_ERR_IO;
    }
    if (exec_sql(r->db, SCHEMA) != NTC_OK) {
        sqlite3_close(r->db);
        free(r);
        return NTC_ERR_INTERNAL;
    }
    *out = r;
    return NTC_OK;
}

void ntc_registry_close(ntc_registry *r) {
    if (!r) return;
    sqlite3_close(r->db);
    free(r);
}

ntc_err ntc_registry_add_service(ntc_registry *r, const char *name, const char *bin) {
    if (!r || !name || !bin) return NTC_ERR_INVALID;
    const char *sql = "INSERT INTO services(name,bin,enabled) VALUES(?1,?2,1) "
                      "ON CONFLICT(name) DO UPDATE SET bin=excluded.bin,enabled=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(r->db, sql, -1, &st, NULL) != SQLITE_OK) return NTC_ERR_INTERNAL;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, bin, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? NTC_OK : NTC_ERR_INTERNAL;
}

ntc_err ntc_registry_remove_service(ntc_registry *r, const char *name) {
    if (!r || !name) return NTC_ERR_INVALID;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(r->db, "DELETE FROM services WHERE name=?1", -1, &st, NULL) != SQLITE_OK)
        return NTC_ERR_INTERNAL;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int changes = sqlite3_changes(r->db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return NTC_ERR_INTERNAL;
    return changes > 0 ? NTC_OK : NTC_ERR_NOT_FOUND;
}

ntc_err ntc_registry_add_route(ntc_registry *r, const char *method,
                               const char *pattern, const char *service) {
    if (!r || !method || !pattern || !service) return NTC_ERR_INVALID;
    const char *sql =
        "INSERT INTO routes(method,pattern,service_id) "
        "SELECT ?1,?2,id FROM services WHERE name=?3 "
        "ON CONFLICT(method,pattern) DO UPDATE SET service_id=excluded.service_id";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(r->db, sql, -1, &st, NULL) != SQLITE_OK) return NTC_ERR_INTERNAL;
    sqlite3_bind_text(st, 1, method, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, pattern, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, service, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int changes = sqlite3_changes(r->db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return NTC_ERR_INTERNAL;
    return changes > 0 ? NTC_OK : NTC_ERR_NOT_FOUND; /* service didn't exist */
}

static void copy_text(char *dst, size_t cap, const unsigned char *src) {
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen((const char *)src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

ntc_err ntc_registry_list_services(ntc_registry *r, ntc_service_row *out,
                                   size_t max, size_t *count) {
    if (!r || !out || !count) return NTC_ERR_INVALID;
    *count = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(r->db,
            "SELECT name,bin,enabled FROM services WHERE enabled=1 ORDER BY id",
            -1, &st, NULL) != SQLITE_OK)
        return NTC_ERR_INTERNAL;
    while (*count < max && sqlite3_step(st) == SQLITE_ROW) {
        ntc_service_row *row = &out[*count];
        copy_text(row->name, sizeof row->name, sqlite3_column_text(st, 0));
        copy_text(row->bin, sizeof row->bin, sqlite3_column_text(st, 1));
        row->enabled = sqlite3_column_int(st, 2);
        (*count)++;
    }
    sqlite3_finalize(st);
    return NTC_OK;
}

ntc_err ntc_registry_list_routes(ntc_registry *r, ntc_route_row *out,
                                 size_t max, size_t *count) {
    if (!r || !out || !count) return NTC_ERR_INVALID;
    *count = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(r->db,
            "SELECT r.method,r.pattern,s.name FROM routes r "
            "JOIN services s ON r.service_id=s.id WHERE s.enabled=1 ORDER BY r.id",
            -1, &st, NULL) != SQLITE_OK)
        return NTC_ERR_INTERNAL;
    while (*count < max && sqlite3_step(st) == SQLITE_ROW) {
        ntc_route_row *row = &out[*count];
        copy_text(row->method, sizeof row->method, sqlite3_column_text(st, 0));
        copy_text(row->pattern, sizeof row->pattern, sqlite3_column_text(st, 1));
        copy_text(row->service, sizeof row->service, sqlite3_column_text(st, 2));
        (*count)++;
    }
    sqlite3_finalize(st);
    return NTC_OK;
}

#ifdef UNIT_TEST
#include "ntc/test.h"
#include "ntc/slice.h"

TEST(registry, add_and_list) {
    ntc_registry *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_open(&r, ":memory:"));
    ASSERT_EQ_INT(NTC_OK, ntc_registry_add_service(r, "hello", "/bin/hello"));
    ASSERT_EQ_INT(NTC_OK, ntc_registry_add_route(r, "GET", "/api/hello", "hello"));

    ntc_service_row sv[8]; size_t n = 0;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_list_services(r, sv, 8, &n));
    ASSERT_EQ_UINT(1u, n);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(sv[0].name), "hello"));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(sv[0].bin), "/bin/hello"));

    ntc_route_row rt[8]; size_t m = 0;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_list_routes(r, rt, 8, &m));
    ASSERT_EQ_UINT(1u, m);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(rt[0].pattern), "/api/hello"));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(rt[0].service), "hello"));
    ntc_registry_close(r);
}

TEST(registry, route_to_unknown_service_fails) {
    ntc_registry *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_open(&r, ":memory:"));
    ASSERT_EQ_INT(NTC_ERR_NOT_FOUND, ntc_registry_add_route(r, "GET", "/x", "nope"));
    ntc_registry_close(r);
}

TEST(registry, upsert_keeps_one_service) {
    ntc_registry *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_open(&r, ":memory:"));
    ASSERT_EQ_INT(NTC_OK, ntc_registry_add_service(r, "a", "/bin/a"));
    ASSERT_EQ_INT(NTC_OK, ntc_registry_add_service(r, "a", "/bin/a2"));
    ntc_service_row sv[8]; size_t n = 0;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_list_services(r, sv, 8, &n));
    ASSERT_EQ_UINT(1u, n);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(sv[0].bin), "/bin/a2"));
    ntc_registry_close(r);
}

TEST(registry, remove_cascades_routes) {
    ntc_registry *r = NULL;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_open(&r, ":memory:"));
    ASSERT_EQ_INT(NTC_OK, ntc_registry_add_service(r, "s", "/bin/s"));
    ASSERT_EQ_INT(NTC_OK, ntc_registry_add_route(r, "GET", "/s", "s"));
    ASSERT_EQ_INT(NTC_OK, ntc_registry_remove_service(r, "s"));
    ntc_route_row rt[8]; size_t m = 0;
    ASSERT_EQ_INT(NTC_OK, ntc_registry_list_routes(r, rt, 8, &m));
    ASSERT_EQ_UINT(0u, m);
    ASSERT_EQ_INT(NTC_ERR_NOT_FOUND, ntc_registry_remove_service(r, "s"));
    ntc_registry_close(r);
}
#endif /* UNIT_TEST */
