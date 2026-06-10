/* M9 integration tests: live JWKS-over-HTTPS + ES256.
 *
 * Topology: a "provider" gateway serves the JWKS vectors as static files over
 * TLS; a "resource server" gateway is configured with auth.jwks_url pointing at
 * it (verifying the provider's cert against auth.jwks_ca). We then present real
 * RS256 / ES256 tokens and assert the verify loop works end to end. We also
 * exercise ntc_https_get directly (good CA succeeds, wrong CA is rejected) -
 * that runs in the ASan/UBSan test binary, so the fetch/verify data path is
 * instrumented. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "ntc/https_client.h"
#include "ntc/jwt.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read a token file into out, trimming trailing whitespace. */
static bool read_token(const char *path, char *out, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = '\0';
    while (n && (out[n-1] == '\n' || out[n-1] == '\r' || out[n-1] == ' ')) out[--n] = '\0';
    return n > 0;
}

/* A gateway that serves the JSON vectors over TLS (the JWKS endpoint). */
static pid_t spawn_provider(int port, int tls_port) {
    setenv("NTC_STATIC_DIR", "tests/vectors", 1);
    setenv("NTC_TLS_CERT", "tests/vectors/tls.cert.pem", 1);
    setenv("NTC_TLS_KEY", "tests/vectors/tls.key.pem", 1);
    unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_JWKS_URL");
    unsetenv("NTC_AUTH_JWKS_CA"); unsetenv("NTC_CONTROLLER_BIN");
    char ps[8], ts[8];
    snprintf(ps, sizeof ps, "%d", port);
    snprintf(ts, sizeof ts, "%d", tls_port);
    const char *argv[] = { "./build/ntc", "start", ps, "--no-dashboard", "--tls", ts, NULL };
    pid_t pid = it_spawn(argv);
    unsetenv("NTC_STATIC_DIR"); unsetenv("NTC_TLS_CERT"); unsetenv("NTC_TLS_KEY");
    return pid;
}

/* A gateway whose /api routes are JWT-protected, fetching keys from a live JWKS URL. */
static pid_t spawn_resource_server(int port, const char *jwks_url, const char *ca) {
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_PROTECT", "/api", 1);
    setenv("NTC_AUTH_JWKS_URL", jwks_url, 1);
    setenv("NTC_AUTH_JWKS_CA", ca, 1);
    unsetenv("NTC_STATIC_DIR"); unsetenv("NTC_TLS_CERT"); unsetenv("NTC_TLS_KEY");
    char ps[8];
    snprintf(ps, sizeof ps, "%d", port);
    const char *argv[] = { "./build/ntc", "start", ps, "--no-dashboard", NULL };
    pid_t pid = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_PROTECT");
    unsetenv("NTC_AUTH_JWKS_URL"); unsetenv("NTC_AUTH_JWKS_CA");
    return pid;
}

static int get_with_bearer(int port, const char *path, const char *token,
                           char *resp, size_t cap) {
    char req[4096];
    int n = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n",
        path, token);
    if (n < 0 || (size_t)n >= sizeof req) return -1;
    return it_send(port, req, resp, cap);
}

/* ntc_https_get against a real TLS server: a matching CA verifies, a
 * non-matching CA is rejected (the whole point of bundling roots). */
ITEST(m9, https_get_verifies_cert) {
    it_iso("m9get");
    pid_t prov = spawn_provider(38183, 38184);
    ASSERT_TRUE(prov > 0);
    ASSERT_TRUE(it_wait_port(38184, 4000));

    ntc_ca *ca = ntc_ca_load_pem("tests/vectors/tls.cert.pem");
    ASSERT_NOT_NULL(ca);
    char body[8192], err[80];
    int n = ntc_https_get(ca, "https://localhost:38184/rs256.jwks.json",
                          body, sizeof body, 4000, err, sizeof err);
    ASSERT_TRUE(n > 0);
    ntc_jwks set;
    ASSERT_TRUE(ntc_jwks_parse(body, (size_t)n, &set));
    ASSERT_TRUE(set.count >= 1);
    ntc_ca_free(ca);

    /* a different CA does not match the server cert -> fail closed */
    ntc_ca *bad = ntc_ca_load_pem("tests/vectors/other.cert.pem");
    ASSERT_NOT_NULL(bad);
    char body2[256];
    int n2 = ntc_https_get(bad, "https://localhost:38184/rs256.jwks.json",
                           body2, sizeof body2, 4000, err, sizeof err);
    ASSERT_EQ_INT(-1, n2);
    ntc_ca_free(bad);

    it_stop(prov);
}

/* Full loop: resource server fetches the RS256 JWKS from the provider at
 * startup, then a real RS256 token authorizes; a missing token is 401. */
ITEST(m9, rs256_via_live_jwks) {
    it_iso("m9rsa_p");
    pid_t prov = spawn_provider(38180, 38181);
    ASSERT_TRUE(prov > 0);
    ASSERT_TRUE(it_wait_port(38181, 4000));

    it_iso("m9rsa_r");
    pid_t rs = spawn_resource_server(38182, "https://localhost:38181/rs256.jwks.json",
                                     "tests/vectors/tls.cert.pem");
    ASSERT_TRUE(rs > 0);
    ASSERT_TRUE(it_wait_port(38182, 4000));

    char tok[2048];
    ASSERT_TRUE(read_token("tests/vectors/rs256.token.txt", tok, sizeof tok));

    char resp[8192];
    ASSERT_TRUE(get_with_bearer(38182, "/api/hello", tok, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    /* no Authorization header -> 401 */
    char resp2[4096];
    ASSERT_TRUE(it_get(38182, "/api/hello", resp2, sizeof resp2) > 0);
    ASSERT_EQ_INT(401, it_status(resp2));

    /* garbage token -> 401 */
    char resp3[4096];
    ASSERT_TRUE(get_with_bearer(38182, "/api/hello", "not.a.jwt", resp3, sizeof resp3) > 0);
    ASSERT_EQ_INT(401, it_status(resp3));

    it_stop(rs);
    it_stop(prov);
}

/* Same loop with an ES256 (EC P-256) token + EC JWK. */
ITEST(m9, es256_via_live_jwks) {
    it_iso("m9es_p");
    pid_t prov = spawn_provider(38185, 38186);
    ASSERT_TRUE(prov > 0);
    ASSERT_TRUE(it_wait_port(38186, 4000));

    it_iso("m9es_r");
    pid_t rs = spawn_resource_server(38187, "https://localhost:38186/es256.jwks.json",
                                     "tests/vectors/tls.cert.pem");
    ASSERT_TRUE(rs > 0);
    ASSERT_TRUE(it_wait_port(38187, 4000));

    char tok[2048];
    ASSERT_TRUE(read_token("tests/vectors/es256.token.txt", tok, sizeof tok));

    char resp[8192];
    ASSERT_TRUE(get_with_bearer(38187, "/api/hello", tok, resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    it_stop(rs);
    it_stop(prov);
}
