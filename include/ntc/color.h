/* color.h - shared ANSI color decision for the logger, CLI, and test runner.
 *
 * One place decides whether to emit color: honors an explicit override, then
 * NO_COLOR (off), CLICOLOR_FORCE (on), then isatty(fd). */
#ifndef NTC_COLOR_H
#define NTC_COLOR_H

#include <stdbool.h>

#define NTC_ANSI_RESET  "\x1b[0m"
#define NTC_ANSI_DIM    "\x1b[90m"
#define NTC_ANSI_RED    "\x1b[1;31m"
#define NTC_ANSI_GREEN  "\x1b[1;32m"
#define NTC_ANSI_YELLOW "\x1b[1;33m"
#define NTC_ANSI_BLUE   "\x1b[1;34m"
#define NTC_ANSI_CYAN   "\x1b[1;36m"

/* Global override: -1 auto (default), 0 never, 1 always. */
void ntc_color_set_mode(int mode);

/* Whether color should be emitted for `fd` right now. */
bool ntc_color_enabled_fd(int fd);

/* `code` if color is enabled for `fd`, otherwise "" - so format strings stay
 * the same and simply collapse to plain text when color is off. */
const char *ntc_colorize(int fd, const char *code);

#endif /* NTC_COLOR_H */
