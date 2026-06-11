/* session_store.h - persistent (SQLite-backed) login sessions.
 *
 * OAuth login sessions live in their OWN SQLite database, separate from the
 * control-plane registry: they churn (created/expired constantly) and we don't
 * want that write load contending with config/route reads. Persisting them means
 * logins survive a gateway restart. Sessions are bounded by *active logins*, not
 * total users, so SQLite is the right size even for a large app. */
#ifndef NTC_SESSION_STORE_H
#define NTC_SESSION_STORE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ntc_session_store ntc_session_store;

/* Open (creating if needed) the sessions DB at `path`. NULL on failure. */
ntc_session_store *ntc_session_store_open(const char *path);
void ntc_session_store_close(ntc_session_store *s);

/* Create or replace session `id` -> (sub, scope), expiring at `expiry` (unix
 * seconds). Returns false on a write error. */
bool ntc_session_put(ntc_session_store *s, const char *id, const char *sub,
                     const char *scope, long expiry);

/* Look up a non-expired session by `id` (relative to `now`), filling sub/scope.
 * Returns false on miss or if expired. */
bool ntc_session_get(ntc_session_store *s, const char *id, long now,
                     char *sub, size_t subcap, char *scope, size_t scopecap);

/* Delete a session (logout). */
void ntc_session_del(ntc_session_store *s, const char *id);

/* Delete all sessions whose expiry has passed. Returns rows removed (or -1). */
int ntc_session_sweep(ntc_session_store *s, long now);

#endif /* NTC_SESSION_STORE_H */
