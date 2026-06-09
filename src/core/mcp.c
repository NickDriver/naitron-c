#define _GNU_SOURCE
#include "ntc/mcp.h"

#include "ntc/arena.h"
#include "ntc/control.h"
#include "ntc/json.h"
#include "ntc/slice.h"
#include "ntc/version.h"

#include <stdio.h>
#include <stdlib.h>
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
    fprintf(o, ",\"result\":%s}", result_json);
}

static void reply_error(FILE *o, const ntc_json *id, int code, const char *msg) {
    fputs("{\"jsonrpc\":\"2.0\",\"id\":", o);
    write_id(o, id);
    fprintf(o, ",\"error\":{\"code\":%d,\"message\":\"%s\"}}", code, msg);
}

static void reply_content(FILE *o, const ntc_json *id, const char *text, bool is_error) {
    char esc[16384];
    if (ntc_json_escape(esc, sizeof esc, ntc_slice_cstr(text)) < 0) esc[0] = '\0';
    fputs("{\"jsonrpc\":\"2.0\",\"id\":", o);
    write_id(o, id);
    fprintf(o, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"%s\"}],\"isError\":%s}}",
            esc, is_error ? "true" : "false");
}

static bool arg_str(const ntc_json *args, const char *key, char *buf, size_t cap) {
    ntc_slice s = ntc_json_str(ntc_json_get(args, key));
    if (s.len == 0 || s.len >= cap) return false;
    for (size_t i = 0; i < s.len; i++)
        if (s.ptr[i] == ' ' || s.ptr[i] == '\n' || s.ptr[i] == '\r') return false;
    memcpy(buf, s.ptr, s.len);
    buf[s.len] = '\0';
    return true;
}

static void handle_tool_call(FILE *o, const ntc_json *id, const ntc_json *params,
                             ntc_mcp_exec_fn exec, void *ctx) {
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

    char raw[8192];
    raw[0] = '\0';
    exec(ctx, command, raw, sizeof raw);
    size_t n = strlen(raw);
    while (n && (raw[n - 1] == '\n' || raw[n - 1] == '\r')) raw[--n] = '\0';
    reply_content(o, id, raw, strncmp(raw, "OK", 2) != 0);
}

void ntc_mcp_handle(const char *msg, size_t len, ntc_mcp_exec_fn exec, void *ctx,
                    char *out, size_t out_cap) {
    if (out_cap) out[0] = '\0';

    char *mem = NULL;
    size_t memsz = 0;
    FILE *o = open_memstream(&mem, &memsz);
    if (!o) return;

    ntc_arena a;
    if (ntc_arena_init(&a, 64 * 1024) != NTC_OK) { fclose(o); free(mem); return; }
    ntc_json *root = ntc_json_parse(&a, msg, len);
    if (root && root->type == NTC_JSON_OBJ) {
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
            handle_tool_call(o, id, ntc_json_get(root, "params"), exec, ctx);
        } else if (ntc_slice_eq_cstr(method, "ping")) {
            reply_result(o, id, "{}");
        } else if (ntc_slice_eq_cstr(method, "notifications/initialized")) {
            /* notification: no reply */
        } else if (id) {
            reply_error(o, id, -32601, "method not found");
        }
    }
    ntc_arena_destroy(&a);
    fclose(o);
    snprintf(out, out_cap, "%s", mem ? mem : "");
    free(mem);
}

/* stdio adapter executor: talk to the running core over the control socket. */
static void stdio_exec(void *ctx, const char *command, char *out, size_t cap) {
    (void)ctx;
    char token[65];
    if (ntc_control_read_token(token, sizeof token) != NTC_OK) {
        snprintf(out, cap, "ERR no control token found (is the core running?)");
        return;
    }
    if (ntc_control_call(ntc_control_sock_path(), token, command, out, cap) != NTC_OK)
        snprintf(out, cap, "ERR cannot reach the core control socket");
}

int ntc_mcp_run(void) {
    static char line[65536];
    fprintf(stderr, "naitron-c MCP server on stdio (core: %s)\n", ntc_control_sock_path());
    while (fgets(line, sizeof line, stdin)) {
        size_t len = strlen(line);
        if (len == 0) continue;
        char out[32768];
        ntc_mcp_handle(line, len, stdio_exec, NULL, out, sizeof out);
        if (out[0]) { fputs(out, stdout); fputc('\n', stdout); fflush(stdout); }
    }
    return 0;
}

void ntc_mcp_print_tools(int json) {
    if (json) { printf("%s\n", TOOLS_JSON); return; }
    printf("naitron-c MCP tools:\n");
    printf("  naitron_status            core status\n");
    printf("  naitron_list_services     list services\n");
    printf("  naitron_list_routes       list routes\n");
    printf("  naitron_add_service       {name, bin}        register + spawn a controller (live)\n");
    printf("  naitron_add_route         {method, pattern, service}   route to a service (live)\n");
    printf("  naitron_remove_service    {name}             remove a service\n");
}
