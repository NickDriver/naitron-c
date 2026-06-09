#include "ntc/signal.h"

#include <execinfo.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static void write_str(const char *s) {
    /* async-signal-safe: plain write(2), no stdio */
    ssize_t r = write(STDERR_FILENO, s, strlen(s));
    (void)r;
}

static void crash_handler(int sig) {
    write_str("\n[naitron-c] FATAL: caught ");
    switch (sig) {
        case SIGSEGV: write_str("SIGSEGV"); break;
        case SIGBUS:  write_str("SIGBUS");  break;
        case SIGFPE:  write_str("SIGFPE");  break;
        case SIGILL:  write_str("SIGILL");  break;
        case SIGABRT: write_str("SIGABRT"); break;
        default:      write_str("signal");  break;
    }
    write_str(" - backtrace:\n");

    void *frames[64];
    int n = backtrace(frames, 64);
    backtrace_symbols_fd(frames, n, STDERR_FILENO);

    /* Restore default and re-raise so the OS reports the real exit/core. */
    signal(sig, SIG_DFL);
    raise(sig);
}

void ntc_install_signal_handlers(void) {
    /* A write to a closed peer must never terminate the process. */
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}
