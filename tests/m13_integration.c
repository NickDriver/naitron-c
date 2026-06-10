/* M13 integration test: request-body schema validation + typed OpenAPI.
 *
 * A schema is registered for POST /api/echo (requires name:string, age:integer,
 * no extra props). The gateway validates the body before forwarding: a valid
 * body reaches the controller (200), invalid bodies are rejected (400) without
 * ever hitting the controller. The auto /_ntc/openapi.json embeds the schema. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int post_json(int port, const char *path, const char *body, char *resp, size_t cap) {
    char req[2048];
    int n = snprintf(req, sizeof req,
        "POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s", path, strlen(body), body);
    if (n < 0 || (size_t)n >= sizeof req) return -1;
    return it_send(port, req, resp, cap);
}

ITEST(m13, schema_validation_and_openapi) {
    it_iso("m13");
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_CONTROLLER_ROUTE", "POST /api/echo", 1);
    setenv("NTC_SCHEMA_FILE", "tests/vectors/schemas.json", 1);
    const char *argv[] = { "./build/ntc", "start", "38230", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_CONTROLLER_ROUTE"); unsetenv("NTC_SCHEMA_FILE");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38230, 4000));

    char resp[4096];

    /* valid body -> reaches the controller -> 200 */
    ASSERT_TRUE(post_json(38230, "/api/echo", "{\"name\":\"bob\",\"age\":30}", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    /* missing required field -> 400 (never forwarded) */
    ASSERT_TRUE(post_json(38230, "/api/echo", "{\"name\":\"bob\"}", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(400, it_status(resp));
    ASSERT_TRUE(strstr(resp, "validation failed") != NULL);
    ASSERT_TRUE(strstr(resp, "age") != NULL);

    /* wrong type (age must be integer) -> 400 */
    ASSERT_TRUE(post_json(38230, "/api/echo", "{\"name\":\"bob\",\"age\":\"x\"}", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(400, it_status(resp));

    /* extra property (additionalProperties:false) -> 400 */
    ASSERT_TRUE(post_json(38230, "/api/echo", "{\"name\":\"bob\",\"age\":1,\"x\":9}", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(400, it_status(resp));

    /* malformed JSON -> 400 */
    ASSERT_TRUE(post_json(38230, "/api/echo", "{not json", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(400, it_status(resp));

    /* typed OpenAPI: the schema is embedded under the route's requestBody */
    char spec[16384];
    ASSERT_TRUE(it_get(38230, "/_ntc/openapi.json", spec, sizeof spec) > 0);
    ASSERT_EQ_INT(200, it_status(spec));
    ASSERT_TRUE(strstr(spec, "/api/echo") != NULL);
    ASSERT_TRUE(strstr(spec, "requestBody") != NULL);
    ASSERT_TRUE(strstr(spec, "\"required\":[\"name\",\"age\"]") != NULL);

    it_stop(srv);
}
