#include "ntc/poller.h"
#ifdef NTC_POLLER_KQUEUE

#include <errno.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

struct ntc_poller {
    int kq;
    void **udata; /* indexed by fd */
    int cap;
};

static ntc_err ensure_cap(ntc_poller *p, int fd) {
    if (fd < p->cap) return NTC_OK;
    int ncap = p->cap ? p->cap : 16;
    while (ncap <= fd) ncap *= 2;
    void **n = realloc(p->udata, (size_t)ncap * sizeof(void *));
    if (!n) return NTC_ERR_OOM;
    for (int i = p->cap; i < ncap; i++) n[i] = NULL;
    p->udata = n;
    p->cap = ncap;
    return NTC_OK;
}

ntc_err ntc_poller_create(ntc_poller **out) {
    if (!out) return NTC_ERR_INVALID;
    ntc_poller *p = calloc(1, sizeof *p);
    if (!p) return NTC_ERR_OOM;
    p->kq = kqueue();
    if (p->kq < 0) { free(p); return NTC_ERR_IO; }
    *out = p;
    return NTC_OK;
}

void ntc_poller_destroy(ntc_poller *p) {
    if (!p) return;
    if (p->kq >= 0) close(p->kq);
    free(p->udata);
    free(p);
}

static ntc_err apply(ntc_poller *p, int fd, uint32_t events) {
    struct kevent ch[2], out[2];
    EV_SET(&ch[0], (uintptr_t)fd, EVFILT_READ,
           ((events & NTC_POLL_READ) ? (EV_ADD | EV_ENABLE) : EV_DELETE) | EV_RECEIPT,
           0, 0, NULL);
    EV_SET(&ch[1], (uintptr_t)fd, EVFILT_WRITE,
           ((events & NTC_POLL_WRITE) ? (EV_ADD | EV_ENABLE) : EV_DELETE) | EV_RECEIPT,
           0, 0, NULL);
    int r = kevent(p->kq, ch, 2, out, 2, NULL);
    if (r < 0) return NTC_ERR_IO;
    for (int i = 0; i < r; i++) {
        /* EV_RECEIPT makes every change echo back with EV_ERROR + errno in data;
         * 0 means success, ENOENT means "wasn't registered" which is fine. */
        if ((out[i].flags & EV_ERROR) && out[i].data != 0 && out[i].data != ENOENT)
            return NTC_ERR_IO;
    }
    return NTC_OK;
}

ntc_err ntc_poller_add(ntc_poller *p, int fd, uint32_t events, void *udata) {
    if (!p || fd < 0) return NTC_ERR_INVALID;
    NTC_TRY(ensure_cap(p, fd));
    p->udata[fd] = udata;
    return apply(p, fd, events);
}

ntc_err ntc_poller_mod(ntc_poller *p, int fd, uint32_t events, void *udata) {
    if (!p || fd < 0 || fd >= p->cap) return NTC_ERR_INVALID;
    p->udata[fd] = udata;
    return apply(p, fd, events);
}

ntc_err ntc_poller_del(ntc_poller *p, int fd) {
    if (!p || fd < 0 || fd >= p->cap) return NTC_ERR_INVALID;
    p->udata[fd] = NULL;
    return apply(p, fd, 0);
}

int ntc_poller_wait(ntc_poller *p, ntc_poll_event *evs, int max, int timeout_ms) {
    if (!p || !evs || max <= 0) return -1;
    if (max > 256) max = 256;
    struct kevent kevs[256];

    struct timespec ts, *tp = NULL;
    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        tp = &ts;
    }

    int r = kevent(p->kq, NULL, 0, kevs, max, tp);
    if (r < 0) return (errno == EINTR) ? 0 : -1;

    int out = 0;
    for (int i = 0; i < r; i++) {
        if (kevs[i].flags & EV_ERROR) continue;
        int fd = (int)kevs[i].ident;
        uint32_t ev = 0;
        if (kevs[i].filter == EVFILT_READ)  ev |= NTC_POLL_READ;
        if (kevs[i].filter == EVFILT_WRITE) ev |= NTC_POLL_WRITE;
        evs[out].fd = fd;
        evs[out].events = ev;
        evs[out].udata = (fd >= 0 && fd < p->cap) ? p->udata[fd] : NULL;
        out++;
    }
    return out;
}

const char *ntc_poller_backend(void) { return "kqueue"; }

#else
typedef int ntc_poller_kqueue_unused_; /* keep this TU non-empty on Linux */
#endif /* NTC_POLLER_KQUEUE */
