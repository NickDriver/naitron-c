/* oauth_mock.c - a minimal mock OIDC token endpoint, for testing the gateway's
 * OAuth2 login flow. Any request gets a token response whose id_token is a
 * fixed HS256 JWT (sub=alice) signed with the secret "oauth-test-secret"; the
 * gateway validates it with oauth.client_secret. Real IdPs sign per-request and
 * validate the code/PKCE - this stand-in only needs to return a valid token. */
#define _GNU_SOURCE
#include "ntc/controller.h"

/* sub=alice, scope="openid profile", exp=4102444800 (year 2100), HS256 over
 * the secret "oauth-test-secret". */
static const char *ID_TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJhbGljZSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0."
    "EE7TRu9qSUNN4nXFLWy3e3eTCEm8K6iAM-rKriEdmK4";

static int handle(const ntc_request *req, ntc_response *res, ntc_arena *a, void *u) {
    (void)req; (void)u;
    return ntc_reply_json(res, a, 200,
        "{\"access_token\":\"mock-access\",\"token_type\":\"Bearer\","
        "\"expires_in\":3600,\"id_token\":\"%s\"}", ID_TOKEN);
}

int main(void) {
    ntc_controller ctl = { .name = "oauthmock", .handle = handle, .udata = NULL };
    return ntc_controller_run(&ctl);
}
