/* mcp.h - built-in MCP (Model Context Protocol) server.
 *
 * `ntc mcp` runs a JSON-RPC stdio server that exposes the control plane as MCP
 * tools, so an AI client (e.g. Claude) can inspect and manage services/routes.
 * It connects to the running core via the same authenticated control socket the
 * CLI uses. */
#ifndef NTC_MCP_H
#define NTC_MCP_H

/* Run the MCP stdio loop until stdin closes. Returns a process exit code. */
int ntc_mcp_run(void);

#endif /* NTC_MCP_H */
