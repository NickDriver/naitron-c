#include "ntc/poller.h"
#ifdef NTC_POLLER_EPOLL

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

struct ntc_poller {
    int ep;
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

static uint32_t to_epoll(uint32_t events) {
    uint32_t e = 0;
    if (events & NTC_POLL_READ)  e |= EPOLLIN;
    if (events & NTC_POLL_WRITE) e |= EPOLLOUT;
    return e;
}

ntc_err ntc_poller_create(ntc_poller **out) {
    if (!out) return NTC_ERR_INVALID;
    ntc_poller *p = calloc(1, sizeof *p);
    if (!p) return NTC_ERR_OOM;
    p->ep = epoll_create1(EPOLL_CLOEXEC);
    if (p->ep < 0) { free(p); return NTC_ERR_IO; }
    *out = p;
    return NTC_OK;
}

void ntc_poller_destroy(ntc_poller *p) {
    if (!p) return;
    if (p->ep >= 0) close(p->ep);
    free(p->udata);
    free(p);
}

ntc_err ntc_poller_add(ntc_poller *p, int fd, uint32_t events, void *udata) {
    if (!p || fd < 0) return NTC_ERR_INVALID;
    NTC_TRY(ensure_cap(p, fd));
    p->udata[fd] = udata;
    struct epoll_event ev = { .events = to_epoll(events), .data = { .fd = fd } };
    return epoll_ctl(p->ep, EPOLL_CTL_ADD, fd, &ev) < 0 ? NTC_ERR_IO : NTC_OK;
}

ntc_err ntc_poller_mod(ntc_poller *p, int fd, uint32_t events, void *udata) {
    if (!p || fd < 0 || fd >= p->cap) return NTC_ERR_INVALID;
    p->udata[fd] = udata;
    struct epoll_event ev = { .events = to_epoll(events), .data = { .fd = fd } };
    return epoll_ctl(p->ep, EPOLL_CTL_MOD, fd, &ev) < 0 ? NTC_ERR_IO : NTC_OK;
}

ntc_err ntc_poller_del(ntc_poller *p, int fd) {
    if (!p || fd < 0 || fd >= p->cap) return NTC_ERR_INVALID;
    p->udata[fd] = NULL;
    return epoll_ctl(p->ep, EPOLL_CTL_DEL, fd, NULL) < 0 ? NTC_ERR_IO : NTC_OK;
}

int ntc_poller_wait(ntc_poller *p, ntc_poll_event *evs, int max, int timeout_ms) {
    if (!p || !evs || max <= 0) return -1;
    if (max > 256) max = 256;
    struct epoll_event eevs[256];

    int r = epoll_wait(p->ep, eevs, max, timeout_ms);
    if (r < 0) return (errno == EINTR) ? 0 : -1;

    for (int i = 0; i < r; i++) {
        int fd = eevs[i].data.fd;
        uint32_t ev = 0;
        if (eevs[i].events & EPOLLIN)  ev |= NTC_POLL_READ;
        if (eevs[i].events & EPOLLOUT) ev |= NTC_POLL_WRITE;
        if (eevs[i].events & (EPOLLHUP | EPOLLERR)) ev |= NTC_POLL_READ | NTC_POLL_WRITE;
        evs[i].fd = fd;
        evs[i].events = ev;
        evs[i].udata = (fd >= 0 && fd < p->cap) ? p->udata[fd] : NULL;
    }
    return r;
}

const char *ntc_poller_backend(void) { return "epoll"; }

#else
typedef int ntc_poller_epoll_unused_; /* keep this TU non-empty on non-Linux */
#endif /* NTC_POLLER_EPOLL */
