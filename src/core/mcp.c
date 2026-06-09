#define _GNU_SOURCE
#include "ntc/mcp.h"

#include "ntc/arena.h"
#include "ntc/control.h"
#include "ntc/json.h"
#include "ntc/slice.h"
#include "ntc/version.h"

#include <stdio.h>
#include <string.h>

static const char *TOOLS_JSON =
"["
 "{\"name\":\"naitron_status\",\"description\":\"Core status: service/route counts and event-loop backend.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
 "{\"name\":\"naitron_list_services\",\"description\":\"List registered services.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
 "{\"name\":\"naitron_list_routes\",\"description\":\"List registered routes.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
 "{\"name\":\"naitron_add_service\",\"description\":\"Register and spawn a controller process (takes effect live).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"bin\":{\"type\":\"string\"}},\"required\":[\"name\",\"bin\"]}},"
 "{\"name\":\"naitron_add_route\",\"description\":\"Route a method+path to a service (takes effect live).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"method\":{\"type\":\"string\"},\"pattern\":{\"type\":\"string\"},\"service\":{\"type\":\"string\"}},\"required\":[\"method\",\"pattern\",\"service\"]}},"
 "{\"name\":\"naitron_remove_service\",\"description\":\"Remove a service.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}}"
"]";

static void write_id(FILE *o, const ntc_json *id) {
    if (id && id->type == NTC_JSON_NUM) { fprintf(o, "%lld", (long long)id->num); return; }
    if (id && id->type == NTC_JSON_STR) {
        char esc[256];
        if (ntc_json_escape(esc, sizeof esc, id->str) >= 0) { fprintf(o, "\"%s\"", esc); return; }
    }
    fputs("null", o);
}

static void reply_result(FILE *o, const ntc_json *id, const char *result_json) {
    fputs("{\"jsonrpc\":\"2.0\",\"id\":", o);
    write_id(o, id);
    fprintf(o, ",\"result\":%s}\n", result_json);
    fflush(o);
}

static void reply_error(FILE *o, const ntc_json *id, int code, const char *msg) {
    fputs("{\"jsonrpc\":\"2.0\",\"id\":", o);
    write_id(o, id);
    fprintf(o, ",\"error\":{\"code\":%d,\"message\":\"%s\"}}\n", code, msg);
    fflush(o);
}

static void reply_content(FILE *o, const ntc_json *id, const char *text, bool is_error) {
    char esc[16384];
    if (ntc_json_escape(esc, sizeof esc, ntc_slice_cstr(text)) < 0) esc[0] = '\0';
    fputs("{\"jsonrpc\":\"2.0\",\"id\":", o);
    write_id(o, id);
    fprintf(o, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"%s\"}],\"isError\":%s}}\n",
            esc, is_error ? "true" : "false");
    fflush(o);
}

/* Pull a control-safe string arg (no spaces/newlines) from arguments. */
static bool arg_str(const ntc_json *args, const char *key, char *buf, size_t cap) {
    ntc_slice s = ntc_json_str(ntc_json_get(args, key));
    if (s.len == 0 || s.len >= cap) return false;
    for (size_t i = 0; i < s.len; i++)
        if (s.ptr[i] == ' ' || s.ptr[i] == '\n' || s.ptr[i] == '\r') return false;
    memcpy(buf, s.ptr, s.len);
    buf[s.len] = '\0';
    return true;
}

static void handle_tool_call(FILE *o, const ntc_json *id, const ntc_json *params) {
    ntc_slice name = ntc_json_str(ntc_json_get(params, "name"));
    const ntc_json *args = ntc_json_get(params, "arguments");
    char command[1024], a[256], b[256], c[256];

    if (ntc_slice_eq_cstr(name, "naitron_status")) snprintf(command, sizeof command, "status");
    else if (ntc_slice_eq_cstr(name, "naitron_list_services")) snprintf(command, sizeof command, "service-list");
    else if (ntc_slice_eq_cstr(name, "naitron_list_routes")) snprintf(command, sizeof command, "route-list");
    else if (ntc_slice_eq_cstr(name, "naitron_add_service")) {
        if (!arg_str(args, "name", a, sizeof a) || !arg_str(args, "bin", b, sizeof b)) {
            reply_content(o, id, "invalid or missing 'name'/'bin'", true); return;
        }
        snprintf(command, sizeof command, "service-add %s %s", a, b);
    } else if (ntc_slice_eq_cstr(name, "naitron_add_route")) {
        if (!arg_str(args, "method", a, sizeof a) || !arg_str(args, "pattern", b, sizeof b) ||
            !arg_str(args, "service", c, sizeof c)) {
            reply_content(o, id, "invalid or missing 'method'/'pattern'/'service'", true); return;
        }
        snprintf(command, sizeof command, "route-add %s %s %s", a, b, c);
    } else if (ntc_slice_eq_cstr(name, "naitron_remove_service")) {
        if (!arg_str(args, "name", a, sizeof a)) { reply_content(o, id, "invalid or missing 'name'", true); return; }
        snprintf(command, sizeof command, "service-rm %s", a);
    } else {
        reply_content(o, id, "unknown tool", true);
        return;
    }

    char token[65];
    if (ntc_control_read_token(token, sizeof token) != NTC_OK) {
        reply_content(o, id, "no control token found (is the core running?)", true);
        return;
    }
    char out[8192];
    if (ntc_control_call(ntc_control_sock_path(), token, command, out, sizeof out) != NTC_OK) {
        reply_content(o, id, "cannot reach the core control socket", true);
        return;
    }
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    reply_content(o, id, out, strncmp(out, "OK", 2) != 0);
}

int ntc_mcp_run(void) {
    static char line[65536];
    FILE *o = stdout;

    while (fgets(line, sizeof line, stdin)) {
        size_t len = strlen(line);
        if (len == 0) continue;

        ntc_arena a;
        if (ntc_arena_init(&a, 64 * 1024) != NTC_OK) break;
        ntc_json *root = ntc_json_parse(&a, line, len);
        if (!root || root->type != NTC_JSON_OBJ) { ntc_arena_destroy(&a); continue; }

        ntc_slice method = ntc_json_str(ntc_json_get(root, "method"));
        const ntc_json *id = ntc_json_get(root, "id");

        if (ntc_slice_eq_cstr(method, "initialize")) {
            reply_result(o, id,
                "{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{\"listChanged\":false}},"
                "\"serverInfo\":{\"name\":\"" NTC_NAME "\",\"version\":\"" NTC_VERSION "\"}}");
        } else if (ntc_slice_eq_cstr(method, "tools/list")) {
            char buf[8192];
            snprintf(buf, sizeof buf, "{\"tools\":%s}", TOOLS_JSON);
            reply_result(o, id, buf);
        } else if (ntc_slice_eq_cstr(method, "tools/call")) {
            handle_tool_call(o, id, ntc_json_get(root, "params"));
        } else if (ntc_slice_eq_cstr(method, "ping")) {
            reply_result(o, id, "{}");
        } else if (ntc_slice_eq_cstr(method, "notifications/initialized")) {
            /* notification: no reply */
        } else if (id) {
            reply_error(o, id, -32601, "method not found");
        }
        ntc_arena_destroy(&a);
    }
    return 0;
}
