/* poller.h - portable readiness event loop (kqueue on BSD/macOS, epoll on Linux).
 *
 * One narrow interface; the backend is chosen at compile time. The server and
 * (later) the orchestrator drive everything through this. udata is associated
 * with each fd and handed back on every event. */
#ifndef NTC_POLLER_H
#define NTC_POLLER_H

#include <stdint.h>
#include "ntc/err.h"

#if defined(__linux__)
#  define NTC_POLLER_EPOLL 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__) || defined(__DragonFly__)
#  define NTC_POLLER_KQUEUE 1
#else
#  error "naitron-c: no supported poller backend for this platform"
#endif

enum {
    NTC_POLL_READ  = 1u << 0,
    NTC_POLL_WRITE = 1u << 1,
};

typedef struct ntc_poller ntc_poller;

typedef struct ntc_poll_event {
    int fd;
    uint32_t events; /* NTC_POLL_READ / NTC_POLL_WRITE that became ready */
    void *udata;     /* whatever was registered for this fd */
} ntc_poll_event;

NTC_NODISCARD ntc_err ntc_poller_create(ntc_poller **out);
void ntc_poller_destroy(ntc_poller *p);

NTC_NODISCARD ntc_err ntc_poller_add(ntc_poller *p, int fd, uint32_t events, void *udata);
NTC_NODISCARD ntc_err ntc_poller_mod(ntc_poller *p, int fd, uint32_t events, void *udata);
NTC_NODISCARD ntc_err ntc_poller_del(ntc_poller *p, int fd);

/* Wait up to timeout_ms (-1 = forever) and fill evs[0..max). Returns the event
 * count (>=0), or -1 on a real error (errno set). EINTR yields 0. */
int ntc_poller_wait(ntc_poller *p, ntc_poll_event *evs, int max, int timeout_ms);

/* "kqueue" or "epoll" - for logging. */
const char *ntc_poller_backend(void);

#endif /* NTC_POLLER_H */
