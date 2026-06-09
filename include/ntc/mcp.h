/* mcp.h - built-in MCP (Model Context Protocol) server.
 *
 * `ntc mcp` runs a JSON-RPC stdio server that exposes the control plane as MCP
 * tools, so an AI client (e.g. Claude) can inspect and manage services/routes.
 * It connects to the running core via the same authenticated control socket the
 * CLI uses. */
#ifndef NTC_MCP_H
#define NTC_MCP_H

#include <stddef.h>

/* Runs a control command (without token) and writes the reply ("OK.."/"ERR..")
 * into out. The two transports supply different executors: the stdio adapter
 * goes over the control socket; the in-core HTTP transport calls the gateway
 * directly. */
typedef void (*ntc_mcp_exec_fn)(void *ctx, const char *command, char *out, size_t out_cap);

/* Handle one JSON-RPC message (msg[0..len)). Writes the JSON-RPC response line
 * into out, or leaves out empty for notifications. */
void ntc_mcp_handle(const char *msg, size_t len, ntc_mcp_exec_fn exec, void *ctx,
                    char *out, size_t out_cap);

/* Run the MCP stdio loop until stdin closes (uses the control socket). */
int ntc_mcp_run(void);

/* Print the tool list (for `ntc mcp tools`). json=1 emits raw JSON. */
void ntc_mcp_print_tools(int json);

#endif /* NTC_MCP_H */
