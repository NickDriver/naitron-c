/* M1 integration tests: reserved namespace, landing, dashboard, metrics, MCP/HTTP. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void read_token(char *out, size_t cap) {
    out[0] = '\0';
    const char *tf = getenv("NTC_TOKEN_FILE");
    if (!tf) return;
    FILE *f = fopen(tf, "r");
    if (!f) return;
    if (fgets(out, (int)cap, f)) {
        size_t n = strlen(out);
        while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    }
    fclose(f);
}

ITEST(m1, reserved_namespace_and_landing) {
    it_iso("m1ns");
    const char *argv[] = { "./build/ntc", "start", "38090", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38090, 4000));

    char resp[8192];
    ASSERT_TRUE(it_get(38090, "/_ntc/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"status\":\"ok\"") != NULL);

    ASSERT_TRUE(it_get(38090, "/_ntc/ready", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    ASSERT_TRUE(it_get(38090, "/_ntc/bogus", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(404, it_status(resp));

    ASSERT_TRUE(it_get(38090, "/", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "text/html") != NULL);
    ASSERT_TRUE(strstr(resp, "powered by naitron-c") != NULL);

    it_stop(srv);
}

ITEST(m1, dashboard_and_metrics) {
    it_iso("m1dash");
    const char *argv[] = { "./build/ntc", "start", "38091", "--dashboard", "38092", NULL };
    pid_t srv = it_spawn(argv);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38091, 4000));
    ASSERT_TRUE(it_wait_port(38092, 4000));

    /* generate one request so metrics are non-zero */
    char resp[8192];
    (void)it_get(38091, "/health", resp, sizeof resp);

    ASSERT_TRUE(it_get(38092, "/", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "naitron-c") != NULL);

    ASSERT_TRUE(it_get(38092, "/api/stats", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"requests_total\"") != NULL);

    ASSERT_TRUE(it_get(38092, "/_ntc/metrics", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "ntc_requests_total") != NULL);

    it_stop(srv);
}

ITEST(m1, mcp_over_http) {
    it_iso("m1mcp");
    const char *argv[] = { "./build/ntc", "start", "38093", "--dashboard", "38094", NULL };
    pid_t srv = it_spawn(argv);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38094, 4000));

    char token[128];
    read_token(token, sizeof token);
    ASSERT_TRUE(strlen(token) > 0);

    const char *body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
    char req[1024], resp[8192];
    snprintf(req, sizeof req,
        "POST /_ntc/mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n"
        "Content-Length: %zu\r\n\r\n%s", token, strlen(body), body);
    ASSERT_TRUE(it_send(38094, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "naitron_status") != NULL);

    /* without the token -> 401 */
    snprintf(req, sizeof req,
        "POST /_ntc/mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: %zu\r\n\r\n%s",
        strlen(body), body);
    ASSERT_TRUE(it_send(38094, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    it_stop(srv);
}
