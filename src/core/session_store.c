#define _GNU_SOURCE
#include "ntc/session_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ntc_session_store { sqlite3 *db; };

ntc_session_store *ntc_session_store_open(const char *path) {
    if (!path || !path[0]) return NULL;
    ntc_session_store *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    if (sqlite3_open(path, &s->db) != SQLITE_OK) {
        sqlite3_close(s->db);
        free(s);
        return NULL;
    }
    /* WAL + NORMAL: sessions favor throughput over fsync-per-commit durability;
     * losing the last few on a hard crash is acceptable, committed ones survive. */
    char *err = NULL;
    const char *init =
        "PRAGMA journal_mode=WAL;"
        "PRAGMA synchronous=NORMAL;"
        "CREATE TABLE IF NOT EXISTS sessions("
        "  id TEXT PRIMARY KEY,"
        "  sub TEXT NOT NULL,"
        "  scope TEXT NOT NULL,"
        "  expiry INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expiry);";
    if (sqlite3_exec(s->db, init, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        sqlite3_close(s->db);
        free(s);
        return NULL;
    }
    return s;
}

void ntc_session_store_close(ntc_session_store *s) {
    if (!s) return;
    sqlite3_close(s->db);
    free(s);
}

bool ntc_session_put(ntc_session_store *s, const char *id, const char *sub,
                     const char *scope, long expiry) {
    if (!s || !id) return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT OR REPLACE INTO sessions(id, sub, scope, expiry) VALUES(?1,?2,?3,?4)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, sub ? sub : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, scope ? scope : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)expiry);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

bool ntc_session_get(ntc_session_store *s, const char *id, long now,
                     char *sub, size_t subcap, char *scope, size_t scopecap) {
    if (!s || !id) return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "SELECT sub, scope FROM sessions WHERE id=?1 AND expiry > ?2",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)now);
    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *su = sqlite3_column_text(st, 0);
        const unsigned char *sc = sqlite3_column_text(st, 1);
        if (sub && subcap) snprintf(sub, subcap, "%s", su ? (const char *)su : "");
        if (scope && scopecap) snprintf(scope, scopecap, "%s", sc ? (const char *)sc : "");
        ok = true;
    }
    sqlite3_finalize(st);
    return ok;
}

void ntc_session_del(ntc_session_store *s, const char *id) {
    if (!s || !id) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "DELETE FROM sessions WHERE id=?1", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

int ntc_session_sweep(ntc_session_store *s, long now) {
    if (!s) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "DELETE FROM sessions WHERE expiry <= ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? sqlite3_changes(s->db) : -1;
}

#ifdef UNIT_TEST
#include "ntc/test.h"
#include <unistd.h>

TEST(session_store, put_get_del_expire) {
    const char *path = "/tmp/ntc_sess_test.db";
    unlink(path); unlink("/tmp/ntc_sess_test.db-wal"); unlink("/tmp/ntc_sess_test.db-shm");
    ntc_session_store *s = ntc_session_store_open(path);
    ASSERT_NOT_NULL(s);

    ASSERT_TRUE(ntc_session_put(s, "sid1", "alice", "openid profile", 2000));
    char sub[128], scope[256];
    ASSERT_TRUE(ntc_session_get(s, "sid1", 1000, sub, sizeof sub, scope, sizeof scope));
    ASSERT_TRUE(strcmp(sub, "alice") == 0);
    ASSERT_TRUE(strcmp(scope, "openid profile") == 0);

    /* expired relative to now=3000 */
    ASSERT_FALSE(ntc_session_get(s, "sid1", 3000, sub, sizeof sub, scope, sizeof scope));
    /* unknown id */
    ASSERT_FALSE(ntc_session_get(s, "nope", 1000, sub, sizeof sub, scope, sizeof scope));

    /* logout */
    ntc_session_del(s, "sid1");
    ASSERT_FALSE(ntc_session_get(s, "sid1", 1000, sub, sizeof sub, scope, sizeof scope));

    ntc_session_store_close(s);
    unlink(path); unlink("/tmp/ntc_sess_test.db-wal"); unlink("/tmp/ntc_sess_test.db-shm");
}

TEST(session_store, survives_reopen) {
    const char *path = "/tmp/ntc_sess_persist.db";
    unlink(path); unlink("/tmp/ntc_sess_persist.db-wal"); unlink("/tmp/ntc_sess_persist.db-shm");
    /* write, close (simulating a restart), reopen, and the session is still there */
    ntc_session_store *s = ntc_session_store_open(path);
    ASSERT_NOT_NULL(s);
    ASSERT_TRUE(ntc_session_put(s, "sidP", "bob", "read", 9999999999L));
    ntc_session_store_close(s);

    ntc_session_store *s2 = ntc_session_store_open(path);
    ASSERT_NOT_NULL(s2);
    char sub[128], scope[256];
    ASSERT_TRUE(ntc_session_get(s2, "sidP", 1000, sub, sizeof sub, scope, sizeof scope));
    ASSERT_TRUE(strcmp(sub, "bob") == 0);
    ntc_session_store_close(s2);
    unlink(path); unlink("/tmp/ntc_sess_persist.db-wal"); unlink("/tmp/ntc_sess_persist.db-shm");
}

TEST(session_store, sweep_removes_expired) {
    const char *path = "/tmp/ntc_sess_sweep.db";
    unlink(path); unlink("/tmp/ntc_sess_sweep.db-wal"); unlink("/tmp/ntc_sess_sweep.db-shm");
    ntc_session_store *s = ntc_session_store_open(path);
    ASSERT_NOT_NULL(s);
    ntc_session_put(s, "old1", "a", "", 1000);
    ntc_session_put(s, "old2", "b", "", 1500);
    ntc_session_put(s, "live", "c", "", 9999999999L);
    int removed = ntc_session_sweep(s, 2000); /* removes the two with expiry <= 2000 */
    ASSERT_EQ_INT(2, removed);
    char sub[128], scope[256];
    ASSERT_TRUE(ntc_session_get(s, "live", 1000, sub, sizeof sub, scope, sizeof scope));
    ASSERT_FALSE(ntc_session_get(s, "old1", 1, sub, sizeof sub, scope, sizeof scope));
    ntc_session_store_close(s);
    unlink(path); unlink("/tmp/ntc_sess_sweep.db-wal"); unlink("/tmp/ntc_sess_sweep.db-shm");
}
#endif /* UNIT_TEST */
