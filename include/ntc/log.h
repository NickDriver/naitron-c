/* log.h - minimal structured logging to stderr, with ANSI color levels.
 *
 * Color is auto-enabled when stderr is a TTY and NO_COLOR is unset; it can be
 * forced on with CLICOLOR_FORCE or via ntc_log_set_color(). Piped/redirected
 * output stays plain so log files never contain escape codes. */
#ifndef NTC_LOG_H
#define NTC_LOG_H

typedef enum ntc_log_level {
    NTC_LOG_DEBUG,    /* cyan   */
    NTC_LOG_INFO,     /* blue   */
    NTC_LOG_SUCCESS,  /* green  */
    NTC_LOG_WARN,     /* yellow */
    NTC_LOG_ERROR     /* red    */
} ntc_log_level;

void ntc_log(ntc_log_level lvl, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Override color detection: -1 = auto (default), 0 = never, 1 = always. */
void ntc_log_set_color(int mode);

#define NTC_DEBUG(...)   ntc_log(NTC_LOG_DEBUG,   __VA_ARGS__)
#define NTC_INFO(...)    ntc_log(NTC_LOG_INFO,    __VA_ARGS__)
#define NTC_SUCCESS(...) ntc_log(NTC_LOG_SUCCESS, __VA_ARGS__)
#define NTC_WARN(...)    ntc_log(NTC_LOG_WARN,    __VA_ARGS__)
#define NTC_ERROR(...)   ntc_log(NTC_LOG_ERROR,   __VA_ARGS__)

#endif /* NTC_LOG_H */
