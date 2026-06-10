/* M12 integration test: OAuth2 login (auth-code + PKCE) + sessions.
 *
 * Topology: a mock IdP gateway serves a /token endpoint over TLS (returns a
 * fixed HS256 id_token for "alice"); an app gateway is configured with the
 * oauth.* settings pointing at it. We drive the gateway's half of the flow as a
 * browser would: GET /auth/login -> capture state -> GET /auth/callback (the
 * gateway exchanges the code at the mock /token over TLS, validates the
 * id_token, sets a session cookie) -> the session cookie then authorizes a
 * protected route; logout destroys the session. */
#define _GNU_SOURCE
#include "ntc/test.h"
#include "it_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* copy the substring of `resp` after `prefix` up to any char in `stops` */
static bool extract(const char *resp, const char *prefix, const char *stops,
                    char *out, size_t cap) {
    const char *p = strstr(resp, prefix);
    if (!p) return false;
    p += strlen(prefix);
    size_t i = 0;
    while (*p && !strchr(stops, *p) && i + 1 < cap) out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
}

static pid_t spawn_idp(int port, int tls_port) {
    setenv("NTC_CONTROLLER_BIN", "./build/oauth_mock", 1);
    setenv("NTC_CONTROLLER_ROUTE", "POST /token", 1);
    setenv("NTC_TLS_CERT", "tests/vectors/tls.cert.pem", 1);
    setenv("NTC_TLS_KEY", "tests/vectors/tls.key.pem", 1);
    char ps[8], ts[8];
    snprintf(ps, sizeof ps, "%d", port);
    snprintf(ts, sizeof ts, "%d", tls_port);
    const char *argv[] = { "./build/ntc", "start", ps, "--no-dashboard", "--tls", ts, NULL };
    pid_t pid = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_CONTROLLER_ROUTE");
    unsetenv("NTC_TLS_CERT"); unsetenv("NTC_TLS_KEY");
    return pid;
}

static pid_t spawn_app(int port, int idp_tls) {
    char token_url[128];
    snprintf(token_url, sizeof token_url, "https://localhost:%d/token", idp_tls);
    setenv("NTC_CONTROLLER_BIN", "./build/hello_controller", 1);
    setenv("NTC_AUTH_MODE", "jwt", 1);
    setenv("NTC_AUTH_PROTECT", "/api", 1);
    setenv("NTC_OAUTH_AUTHORIZE_URL", "https://idp.example/authorize", 1);
    setenv("NTC_OAUTH_TOKEN_URL", token_url, 1);
    setenv("NTC_OAUTH_CLIENT_ID", "testclient", 1);
    setenv("NTC_OAUTH_CLIENT_SECRET", "oauth-test-secret", 1);
    setenv("NTC_OAUTH_REDIRECT_URI", "http://localhost/auth/callback", 1);
    setenv("NTC_OAUTH_CA", "tests/vectors/tls.cert.pem", 1);
    char ps[8];
    snprintf(ps, sizeof ps, "%d", port);
    const char *argv[] = { "./build/ntc", "start", ps, "--no-dashboard", NULL };
    pid_t pid = it_spawn(argv);
    unsetenv("NTC_CONTROLLER_BIN"); unsetenv("NTC_AUTH_MODE"); unsetenv("NTC_AUTH_PROTECT");
    unsetenv("NTC_OAUTH_AUTHORIZE_URL"); unsetenv("NTC_OAUTH_TOKEN_URL");
    unsetenv("NTC_OAUTH_CLIENT_ID"); unsetenv("NTC_OAUTH_CLIENT_SECRET");
    unsetenv("NTC_OAUTH_REDIRECT_URI"); unsetenv("NTC_OAUTH_CA");
    return pid;
}

static int get_with_cookie(int port, const char *path, const char *cookie, char *resp, size_t cap) {
    char req[1024];
    int n = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: x\r\nCookie: %s\r\nConnection: close\r\n\r\n", path, cookie);
    if (n < 0 || (size_t)n >= sizeof req) return -1;
    return it_send(port, req, resp, cap);
}

ITEST(m12, oauth_login_session_flow) {
    it_iso("m12idp");
    pid_t idp = spawn_idp(38220, 38221);
    ASSERT_TRUE(idp > 0);
    ASSERT_TRUE(it_wait_port(38221, 4000));

    it_iso("m12app");
    pid_t app = spawn_app(38222, 38221);
    ASSERT_TRUE(app > 0);
    ASSERT_TRUE(it_wait_port(38222, 4000));

    /* protected route with no auth -> 401 */
    char r401[2048];
    ASSERT_TRUE(it_get(38222, "/api/hello", r401, sizeof r401) > 0);
    ASSERT_EQ_INT(401, it_status(r401));

    /* /auth/login -> 302 to the IdP authorize URL; capture the state param */
    char rlogin[4096];
    ASSERT_TRUE(it_get(38222, "/auth/login", rlogin, sizeof rlogin) > 0);
    ASSERT_EQ_INT(302, it_status(rlogin));
    ASSERT_TRUE(strstr(rlogin, "code_challenge_method=S256") != NULL);
    char state[64];
    ASSERT_TRUE(extract(rlogin, "state=", "&\r\n", state, sizeof state));

    /* /auth/callback -> gateway exchanges the code at the mock /token over TLS,
     * validates the id_token, and sets a session cookie */
    char cbpath[128], rcb[4096];
    snprintf(cbpath, sizeof cbpath, "/auth/callback?code=testcode&state=%s", state);
    ASSERT_TRUE(it_get(38222, cbpath, rcb, sizeof rcb) > 0);
    ASSERT_EQ_INT(302, it_status(rcb));
    char sid[128];
    ASSERT_TRUE(extract(rcb, "ntc_session=", "; \r\n", sid, sizeof sid));

    char cookie[160];
    snprintf(cookie, sizeof cookie, "ntc_session=%s", sid);

    /* the session cookie now authorizes the protected route, as "alice" */
    char rok[2048];
    ASSERT_TRUE(get_with_cookie(38222, "/api/hello", cookie, rok, sizeof rok) > 0);
    ASSERT_EQ_INT(200, it_status(rok));
    ASSERT_TRUE(strstr(rok, "\"sub\":\"alice\"") != NULL); /* identity propagated to the controller */

    /* logout destroys the session; the same cookie no longer authorizes */
    char rlogout[2048];
    ASSERT_TRUE(get_with_cookie(38222, "/auth/logout", cookie, rlogout, sizeof rlogout) > 0);
    ASSERT_EQ_INT(302, it_status(rlogout));

    char rgone[2048];
    ASSERT_TRUE(get_with_cookie(38222, "/api/hello", cookie, rgone, sizeof rgone) > 0);
    ASSERT_EQ_INT(401, it_status(rgone));

    /* an invalid state at the callback is rejected (CSRF / expired) */
    char rbad[2048];
    ASSERT_TRUE(it_get(38222, "/auth/callback?code=x&state=bogus", rbad, sizeof rbad) > 0);
    ASSERT_EQ_INT(400, it_status(rbad));

    it_stop(app);
    it_stop(idp);
}
