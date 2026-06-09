#include "ntc/log.h"
#include "ntc/color.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

void ntc_log_set_color(int mode) { ntc_color_set_mode(mode); }

void ntc_log(ntc_log_level lvl, const char *fmt, ...) {
    static const char *const names[] = { "DEBUG", "INFO", "OK", "WARN", "ERROR" };
    static const char *const codes[] = {
        NTC_ANSI_CYAN,   /* DEBUG   */
        NTC_ANSI_BLUE,   /* INFO    */
        NTC_ANSI_GREEN,  /* SUCCESS */
        NTC_ANSI_YELLOW, /* WARN    */
        NTC_ANSI_RED,    /* ERROR   */
    };

    int idx = (int)lvl;
    if (idx < 0 || idx > NTC_LOG_ERROR) idx = NTC_LOG_ERROR;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv;
    localtime_r(&ts.tv_sec, &tmv);
    char tbuf[32];
    strftime(tbuf, sizeof tbuf, "%Y-%m-%dT%H:%M:%S", &tmv);
    long ms = ts.tv_nsec / 1000000;

    const int fd = STDERR_FILENO;
    const char *dim   = ntc_colorize(fd, NTC_ANSI_DIM);
    const char *reset = ntc_colorize(fd, NTC_ANSI_RESET);
    const char *clvl  = ntc_colorize(fd, codes[idx]);

    fprintf(stderr, "%s%s.%03ld%s %s[%-5s]%s ",
            dim, tbuf, ms, reset, clvl, names[idx], reset);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}
