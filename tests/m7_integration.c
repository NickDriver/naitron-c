/* M7 integration tests: RS256-JWT auth over HTTP, with the public key supplied
 * as a JWKS file (NTC_AUTH_JWKS_FILE). The matching token/JWKS live in
 * tests/vectors/rs256.* and are also used by the jwt.c unit tests. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* RS256 token, exp = year 2100 (so it never expires during the test). */
static const char *RS256 =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyczI1Ni11c2VyIiwic2NvcGUiOiJyZWFkIH"
    "dyaXRlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9.bdIpNH5kIMXWU0fo-9iLeCn2qQOh"
    "yQh-lhePWNihrNpL4fOLHsEgcXP939b0yboqm3wRWQXYtr9hFKXAEOfANO0fg4z9HDFISPXTjBaWvdSe40q"
    "LSwVkhhgdORnxK-XKglfG7IE105MzyFr1sYMB0FHYmwBaveg5UlNKT3tUL4pD6oxN-lYFI_SBI9f3lpPubQ"
    "kVa-PS59KZ26PSe6hMGcYqQerIVBhs7YZsMYpukRgFHwcF4MDg-ozNOxsR7jm5jpHH6Fkh1WSPrpko1giLN"
    "-ecC4F17IGkmZTqLlVf1RGjJxOBIHRpsgPdrAi9sjy9NzDNguhfrg_zEE6MZr4e0g";

/* HS256 token (jwt.io sample) - must be rejected when only an RS256 key is set. */
static const char *HS256 =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

ITEST(m7, rs256_jwt_auth) {
    it_iso("m7rs256");
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_JWKS_FILE", "tests/vectors/rs256.jwks.json", 1);
    setenv("NTC_AUTH_PROTECT", "/secure", 1);
    const char *argv[] = { "./build/ntc", "start", "38150", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_JWKS_FILE"); unsetenv("NTC_AUTH_PROTECT");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38150, 4000));

    char req[2048], resp[8192];

    /* protected, no token -> 401 */
    ASSERT_TRUE(it_get(38150, "/secure/x", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    /* protected, valid RS256 token -> auth passes (no such route -> 404, not 401) */
    snprintf(req, sizeof req,
        "GET /secure/x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", RS256);
    ASSERT_TRUE(it_send(38150, req, resp, sizeof resp) > 0);
    ASSERT_TRUE(it_status(resp) != 401);

    /* protected, HS256 token but no HMAC secret configured -> 401 */
    snprintf(req, sizeof req,
        "GET /secure/x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", HS256);
    ASSERT_TRUE(it_send(38150, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    /* tampered RS256 token -> 401 */
    snprintf(req, sizeof req,
        "GET /secure/x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %sAAAA\r\n\r\n", RS256);
    ASSERT_TRUE(it_send(38150, req, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    /* unprotected path -> open */
    ASSERT_TRUE(it_get(38150, "/_ntc/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    it_stop(srv);
}

/* TLS termination. The C it_util harness speaks plaintext only, so we drive the
 * HTTPS side with `curl -k` (a committed self-signed localhost cert lives in
 * tests/vectors/tls.*). Skips cleanly if curl is unavailable. */
static bool have_curl(void) { return system("command -v curl >/dev/null 2>&1") == 0; }

/* Run `cmd`, capture trimmed stdout into out. Returns true on a clean exit. */
static bool run_capture(const char *cmd, char *out, size_t cap) {
    FILE *p = popen(cmd, "r");
    if (!p) return false;
    size_t n = fread(out, 1, cap - 1, p);
    out[n] = '\0';
    return pclose(p) == 0;
}

ITEST(m7, tls_termination) {
    if (!have_curl()) SKIP("curl not available");
    it_iso("m7tls");
    setenv("NTC_TLS_CERT", "tests/vectors/tls.cert.pem", 1);
    setenv("NTC_TLS_KEY", "tests/vectors/tls.key.pem", 1);
    const char *argv[] = { "./build/ntc", "start", "38151", "--no-dashboard", "--tls", "38152", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_TLS_CERT"); unsetenv("NTC_TLS_KEY");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38152, 4000)); /* TLS listener accepting */

    char out[4096];

    /* HTTPS GET -> 200 with the health body, proving the handshake + record
     * pump + HTTP layer all work over TLS. */
    ASSERT_TRUE(run_capture(
        "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:38152/_ntc/health",
        out, sizeof out));
    ASSERT_TRUE(strcmp(out, "200") == 0);

    ASSERT_TRUE(run_capture("curl -sk https://127.0.0.1:38152/_ntc/health", out, sizeof out));
    ASSERT_TRUE(strstr(out, "\"status\":\"ok\"") != NULL);

    /* A larger body (landing page) exercises multi-chunk writes through the engine. */
    ASSERT_TRUE(run_capture(
        "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:38152/", out, sizeof out));
    ASSERT_TRUE(strcmp(out, "200") == 0);

    /* Plaintext listener still serves in parallel. */
    char resp[4096];
    ASSERT_TRUE(it_get(38151, "/_ntc/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    it_stop(srv);
}
