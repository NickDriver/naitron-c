/* it_util.h - integration-test helpers: spawn the real ./build/ntc, talk HTTP. */
#ifndef NTC_IT_UTIL_H
#define NTC_IT_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Fork+exec ./build/ntc with argv (NULL-terminated, argv[0] = "./build/ntc").
 * The caller should setenv() isolation vars (NTC_DB/NTC_CONTROL_SOCK/...) first.
 * Returns the child pid, or -1. */
pid_t it_spawn(const char *const argv[]);

/* Poll connect() to 127.0.0.1:port until it accepts or timeout. */
bool it_wait_port(int port, int timeout_ms);

/* Send a raw request to 127.0.0.1:port, read the full response into resp
 * (NUL-terminated). Returns bytes read, or -1. */
int it_send(int port, const char *raw, char *resp, size_t cap);

/* Convenience: GET path, return the response. */
int it_get(int port, const char *path, char *resp, size_t cap);

/* Parse the numeric status code from an HTTP response ("HTTP/1.1 NNN ..."). */
int it_status(const char *resp);

/* SIGTERM the child and reap it. */
void it_stop(pid_t pid);

/* Set isolated temp env (NTC_DB/CONTROL_SOCK/TOKEN_FILE/PID_FILE/LOG_FILE) under
 * /tmp/ntc_it_<tag>.* and remove any stale files. */
void it_iso(const char *tag);

#endif /* NTC_IT_UTIL_H */
