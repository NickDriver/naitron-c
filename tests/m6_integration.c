/* M6 integration tests: static file serving + auto-generated OpenAPI. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

ITEST(m6, static_files) {
    it_iso("m6s");
    const char *dir = "/tmp/ntc_m6_public";
    mkdir(dir, 0755);
    write_file("/tmp/ntc_m6_public/index.html", "<h1>home</h1>");
    write_file("/tmp/ntc_m6_public/app.css", "body{color:red}");
    setenv("NTC_STATIC_DIR", dir, 1);
    const char *argv[] = { "./build/ntc", "start", "38140", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_STATIC_DIR");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38140, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38140, "/", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "<h1>home</h1>") != NULL);

    ASSERT_TRUE(it_get(38140, "/app.css", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "text/css") != NULL);
    ASSERT_TRUE(strstr(resp, "color:red") != NULL);

    /* path traversal is blocked */
    ASSERT_TRUE(it_send(38140,
        "GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(404, it_status(resp));

    it_stop(srv);
    unlink("/tmp/ntc_m6_public/index.html");
    unlink("/tmp/ntc_m6_public/app.css");
    rmdir(dir);
}

ITEST(m6, openapi_generated) {
    it_iso("m6o");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    const char *argv[] = { "./build/ntc", "start", "38141", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38141, 4000));

    char resp[16384];
    ASSERT_TRUE(it_get(38141, "/_ntc/openapi.json", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"openapi\":\"3.0.0\"") != NULL);
    /* :name pattern converted to {name} */
    ASSERT_TRUE(strstr(resp, "/api/hello/{name}") != NULL);

    it_stop(srv);
}
