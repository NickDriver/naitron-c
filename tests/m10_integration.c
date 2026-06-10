/* M10 integration test: `ntc dev` watch + hot-reload.
 *
 * We compile a tiny controller that returns {"v":1}, run it under `ntc dev`
 * with a --build hook watching its source, then rewrite the source to return
 * {"v":2}. The dev loop should detect the source change, run the build, notice
 * the rebuilt binary, and reload the service - so the same URL starts returning
 * the new body without any manual restart. This exercises the full chain
 * (source watch -> build hook -> binary mtime -> reload). */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define M10_SRC "/tmp/ntc_m10_ctl.c"
#define M10_BIN "/tmp/ntc_m10_bin"
#define M10_BUILD \
    "clang -std=c23 -Iinclude " M10_SRC \
    " src/common/controller_sdk.c src/common/wire.c src/common/arena.c" \
    " src/common/slice.c src/common/http_request.c -o " M10_BIN

/* Write the controller source so requests return {"v":<v>}. */
static void write_ctl(int v) {
    FILE *f = fopen(M10_SRC, "w");
    if (!f) return;
    fprintf(f,
        "#define _GNU_SOURCE\n"
        "#include \"ntc/controller.h\"\n"
        "static int handle(const ntc_request *req, ntc_response *res, ntc_arena *a, void *u) {\n"
        "    (void)req; (void)u;\n"
        "    return ntc_reply_json(res, a, 200, \"{\\\"v\\\":%d}\");\n"
        "}\n"
        "int main(void) {\n"
        "    ntc_controller ctl = { .name = \"m10\", .handle = handle, .udata = NULL };\n"
        "    return ntc_controller_run(&ctl);\n"
        "}\n", v);
    fclose(f);
}

ITEST(m10, hot_reload_via_build_hook) {
    it_iso("m10");
    write_ctl(1);
    ASSERT_EQ_INT(0, system(M10_BUILD)); /* initial binary must exist to spawn */

    setenv("NTC_CONTROLLER_BIN", M10_BIN, 1);
    const char *argv[] = { "./build/ntc", "dev", "38190", "--no-dashboard",
                           "--build", M10_BUILD, "--watch", M10_SRC, NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38190, 4000));

    char resp[4096];
    ASSERT_TRUE(it_get(38190, "/api/hello", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"v\":1") != NULL);

    /* edit the source: dev should rebuild + reload */
    write_ctl(2);

    bool got_v2 = false;
    for (int i = 0; i < 60 && !got_v2; i++) {
        char r[4096];
        if (it_get(38190, "/api/hello", r, sizeof r) > 0 && strstr(r, "\"v\":2")) got_v2 = true;
        else usleep(150 * 1000);
    }
    ASSERT_TRUE(got_v2);

    it_stop(srv);
    unlink(M10_SRC);
    unlink(M10_BIN);
}
