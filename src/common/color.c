#include "ntc/color.h"

#include <stdlib.h>
#include <unistd.h>

static int g_mode = -1; /* -1 auto, 0 never, 1 always */

void ntc_color_set_mode(int mode) { g_mode = mode; }

static int detect_fd(int fd) {
    /* cache the env/isatty decision for the usual fds (0,1,2) */
    static int cache[3] = { -1, -1, -1 };
    int *slot = (fd >= 0 && fd <= 2) ? &cache[fd] : NULL;
    if (slot && *slot >= 0) return *slot;

    int v;
    if (getenv("NO_COLOR") != NULL)            v = 0; /* https://no-color.org */
    else if (getenv("CLICOLOR_FORCE") != NULL) v = 1; /* force even when piped */
    else                                       v = isatty(fd) ? 1 : 0;

    if (slot) *slot = v;
    return v;
}

bool ntc_color_enabled_fd(int fd) {
    if (g_mode >= 0) return g_mode != 0;
    return detect_fd(fd) != 0;
}

const char *ntc_colorize(int fd, const char *code) {
    return ntc_color_enabled_fd(fd) ? code : "";
}

#ifdef UNIT_TEST
#include "ntc/test.h"
#include <string.h>

TEST(color, mode_override_controls_output) {
    ntc_color_set_mode(0);
    ASSERT_FALSE(ntc_color_enabled_fd(2));
    ASSERT_EQ_UINT(0u, strlen(ntc_colorize(2, NTC_ANSI_RED)));

    ntc_color_set_mode(1);
    ASSERT_TRUE(ntc_color_enabled_fd(2));
    ASSERT_EQ_INT(0, strcmp(ntc_colorize(2, NTC_ANSI_GREEN), NTC_ANSI_GREEN));

    ntc_color_set_mode(-1); /* restore auto so runner output stays consistent */
}
#endif /* UNIT_TEST */
