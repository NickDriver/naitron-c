/* M7 integration tests: RS256-JWT auth + TLS termination (BearSSL).
 *
 * RS256 keys are supplied as a JWKS file (NTC_AUTH_JWKS_FILE). TLS is driven by
 * a real in-harness BearSSL client (it_tls.*) - no curl dependency - against a
 * committed self-signed localhost cert (tests/vectors/tls.*). */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"
#include "it_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* RS256 token (2048-bit key), exp = year 2100. */
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

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    static char buf[4096];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

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

/* An RSA-4096 key proves the verifier + JWK parsing handle the largest modulus
 * our buffers allow (512 bytes). */
ITEST(m7, rs256_4096_jwt_auth) {
    it_iso("m7rs4096");
    char *tok = slurp("tests/vectors/rs256_4096.token.txt");
    ASSERT_NOT_NULL(tok);
    char token[4096]; snprintf(token, sizeof token, "%s", tok);
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_JWKS_FILE", "tests/vectors/rs256_4096.jwks.json", 1);
    setenv("NTC_AUTH_PROTECT", "/secure", 1);
    const char *argv[] = { "./build/ntc", "start", "38153", "--no-dashboard", NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_JWKS_FILE"); unsetenv("NTC_AUTH_PROTECT");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38153, 4000));

    char req[6144], resp[8192];
    ASSERT_TRUE(it_get(38153, "/secure/x", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    snprintf(req, sizeof req,
        "GET /secure/x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", token);
    ASSERT_TRUE(it_send(38153, req, resp, sizeof resp) > 0);
    ASSERT_TRUE(it_status(resp) != 401);

    it_stop(srv);
}

/* ---- TLS termination (driven by the in-harness BearSSL client) ---- */

static pid_t spawn_tls(int plain, int tls, const char *extra_env_k, const char *extra_env_v) {
    setenv("NTC_TLS_CERT", "tests/vectors/tls.cert.pem", 1);
    setenv("NTC_TLS_KEY", "tests/vectors/tls.key.pem", 1);
    if (extra_env_k) setenv(extra_env_k, extra_env_v, 1);
    char ps[8], ts[8];
    snprintf(ps, sizeof ps, "%d", plain);
    snprintf(ts, sizeof ts, "%d", tls);
    const char *argv[] = { "./build/ntc", "start", ps, "--no-dashboard", "--tls", ts, NULL };
    pid_t srv = it_spawn(argv);
    unsetenv("NTC_TLS_CERT"); unsetenv("NTC_TLS_KEY");
    if (extra_env_k) unsetenv(extra_env_k);
    return srv;
}

ITEST(m7, tls_termination) {
    it_iso("m7tls");
    pid_t srv = spawn_tls(38151, 38152, NULL, NULL);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38152, 4000));

    char resp[8192];

    /* HTTPS GET -> 200 with the health body: handshake + record pump + HTTP all work. */
    ASSERT_TRUE(it_tls_get(38152, "/_ntc/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "\"status\":\"ok\"") != NULL);

    /* a larger body (landing page) over TLS */
    ASSERT_TRUE(it_tls_get(38152, "/", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "powered by naitron-c") != NULL);

    /* the plaintext listener still serves in parallel */
    ASSERT_TRUE(it_get(38151, "/_ntc/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    it_stop(srv);
}

/* A response far larger than the TLS record/app buffers (~16 KB each) forces the
 * server's "fill sendapp -> flush -> pump records -> repeat" loop many times. */
ITEST(m7, tls_large_response) {
    it_iso("m7tlsbig");
    const char *dir = "/tmp/ntc_m7_public";
    mkdir(dir, 0755);
    const size_t SZ = 100000;
    char *content = malloc(SZ + 64);
    ASSERT_NOT_NULL(content);
    for (size_t i = 0; i < SZ; i++) content[i] = (char)('A' + (i % 26));
    memcpy(content + SZ, "END-OF-BIG-FILE-SENTINEL", 25); /* incl NUL */
    FILE *f = fopen("/tmp/ntc_m7_public/big.txt", "wb");
    ASSERT_NOT_NULL(f);
    fwrite(content, 1, SZ + 24, f); fclose(f);

    pid_t srv = spawn_tls(38154, 38155, "NTC_STATIC_DIR", dir);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38155, 4000));

    size_t cap = SZ + 4096;
    char *resp = malloc(cap);
    ASSERT_NOT_NULL(resp);
    int n = it_tls_get(38155, "/big.txt", resp, cap);
    ASSERT_TRUE(n > (int)SZ);                 /* whole body came back over TLS */
    ASSERT_EQ_INT(200, it_status(resp));
    ASSERT_TRUE(strstr(resp, "END-OF-BIG-FILE-SENTINEL") != NULL); /* intact to the last byte */

    it_stop(srv);
    free(content); free(resp);
    unlink("/tmp/ntc_m7_public/big.txt");
    rmdir(dir);
}

/* Many sequential TLS connections: repeated handshakes + per-conn engine
 * lifecycle + close_notify, with no resource accumulation crashing the server. */
ITEST(m7, tls_many_connections) {
    it_iso("m7tlsmany");
    pid_t srv = spawn_tls(38156, 38157, NULL, NULL);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38157, 4000));

    char resp[4096];
    int ok = 0;
    for (int i = 0; i < 30; i++) {
        if (it_tls_get(38157, "/_ntc/health", resp, sizeof resp) > 0 && it_status(resp) == 200)
            ok++;
    }
    ASSERT_EQ_INT(30, ok);
    it_stop(srv);
}

/* The server must survive hostile/non-TLS input on the HTTPS port and keep
 * serving valid clients. */
ITEST(m7, tls_survives_bad_input) {
    it_iso("m7tlsbad");
    pid_t srv = spawn_tls(38158, 38159, NULL, NULL);
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38159, 4000));

    char resp[4096];
    /* Plaintext HTTP sent to the TLS port: the first byte ('G') is an invalid
     * TLS record content-type, so BearSSL fails the handshake immediately and
     * the gateway drops the connection - it must not crash or wedge. */
    (void)it_send(38159, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", resp, sizeof resp);
    (void)it_send(38159, "complete and utter nonsense not a tls record at all", resp, sizeof resp);

    /* server still up and a real TLS client still succeeds */
    ASSERT_TRUE(it_tls_get(38159, "/_ntc/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));
    /* and the plaintext listener too */
    ASSERT_TRUE(it_get(38158, "/_ntc/health", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(200, it_status(resp));

    it_stop(srv);
}

/* TLS + RS256 together: auth is enforced over the encrypted channel. */
ITEST(m7, tls_plus_rs256) {
    it_iso("m7tlsauth");
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_JWKS_FILE", "tests/vectors/rs256.jwks.json", 1);
    setenv("NTC_AUTH_PROTECT", "/secure", 1);
    pid_t srv = spawn_tls(38160, 38161, NULL, NULL);
    unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_JWKS_FILE"); unsetenv("NTC_AUTH_PROTECT");
    ASSERT_TRUE(srv > 0);
    ASSERT_TRUE(it_wait_port(38161, 4000));

    char req[2048], resp[8192];

    /* protected path over TLS, no token -> 401 */
    ASSERT_TRUE(it_tls_get(38161, "/secure/x", resp, sizeof resp) > 0);
    ASSERT_EQ_INT(401, it_status(resp));

    /* protected path over TLS, valid RS256 -> auth passes (404, not 401) */
    snprintf(req, sizeof req,
        "GET /secure/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        "Authorization: Bearer %s\r\n\r\n", RS256);
    ASSERT_TRUE(it_tls_request(38161, req, strlen(req), resp, sizeof resp) > 0);
    ASSERT_TRUE(it_status(resp) != 401);

    it_stop(srv);
}
