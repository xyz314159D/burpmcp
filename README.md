# BurpMcp



## Overview



`BurpMcp` is a Burp Suite extension that exposes Burp functionality to AI clients through the Model Context Protocol (MCP), with a practical focus on bug bounty and web application pentesting.

The project combines low-level Burp primitives such as request replay, Repeater, Intruder, Collaborator, and proxy history access with higher-level workflows that are more useful during real triage:

- endpoint inventory generation from captured traffic
- passive history analysis for common bug bounty signals
- direct replay of captured requests from stable history references
- targeted verification request generation and execution

## Key Capabilities



- Send HTTP/1.1 and HTTP/2 requests from MCP clients with approval controls
- Read and filter proxy HTTP history, WebSocket history, and Organizer items
- Summarize captured traffic into grouped endpoint inventory
- Analyze history for candidate `idor`, `auth`, `input`, `cors`, `cache`, `debug`, `secrets`, `ssrf`, and `websocket` issues
- Replay requests directly from history without rebuilding them manually
- Generate targeted verification requests for common offensive checks
- Execute bounded verification flows and return differential observations
- Create Repeater tabs and send traffic to Intruder
- Generate and poll Burp Collaborator payloads
- Install Claude Desktop integration through the packaged stdio proxy

## Main MCP Tools



### Traffic and Analysis



- `summarize_http_history`
- `analyze_http_history`
- `replay_history_item`
- `generate_verification_requests`
- `run_verification_check`
- `export_finding_bundle`

### Low-Level Burp Operations



- `send_http1_request`
- `send_http2_request`
- `create_repeater_tab`
- `create_repeater_tab_http2`
- `send_to_intruder`
- `get_proxy_http_history`
- `get_proxy_http_history_regex`
- `get_proxy_websocket_history`
- `get_proxy_websocket_history_regex`
- `get_organizer_items`
- `get_organizer_items_regex`

### Utility and Environment



- `generate_collaborator_payload`
- `get_collaborator_interactions`
- `output_project_options`
- `output_user_options`
- `set_project_options`
- `set_user_options`
- `set_task_execution_engine_state`
- `set_proxy_intercept_state`

## Security Model



`BurpMcp` is designed to be useful without removing operator control.

- HTTP requests can require explicit approval
- data access to history and organizer views can require approval
- auto-approve rules support host, host:port, wildcard domain, and URL-prefix formats
- in-scope filtering can be enforced for proxy history access
- active verification flows support preview mode before sending requests

## Requirements



- Burp Suite Professional or Community
- Java 21
- `jar` available in `PATH`

Burp Collaborator and scanner-issue features depend on Burp Professional.

## Build



```
git clone https://github.com/MauricioDuarte100/BurpMcp.git
cd BurpMcp
./gradlew embedProxyJar
```



The packaged extension is generated at:

```
build/libs/BurpMcp-all.jar
```



## Install In Burp Suite



1. Open Burp Suite.
2. Go to `Extensions`.
3. Add a Java extension.
4. Select `build/libs/BurpMcp-all.jar`.
5. Open the `MCP` tab and enable the server.

## Claude Desktop Integration



The extension can install its Claude Desktop entry automatically. It uses the MCP server key `burpmcp`.

Example manual configuration:

```
{
  "mcpServers": {
    "burpmcp": {
      "command": "<path to java>",
      "args": [
        "-jar",
        "/path/to/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876"
      ]
    }
  }
}
```



## Manual MCP Connection



You can connect directly to the SSE server:

```
http://127.0.0.1:9876
```



Or run the packaged stdio proxy:

```
/path/to/java -jar /path/to/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```



## Typical Workflow



1. Capture traffic in Burp Proxy.
2. Use `summarize_http_history` to build endpoint inventory.
3. Use `analyze_http_history` to surface likely attack paths.
4. Replay or send interesting requests to Repeater.
5. Use `generate_verification_requests` or `run_verification_check` for bounded follow-up validation.
6. Export evidence bundles for findings that deserve manual confirmation and reporting.

## Development Notes



- The extension is built on the Burp Montoya API and Ktor.
- The MCP server is embedded into the Burp extension and can also be exposed through the packaged proxy jar.
- Existing low-level tools remain available for clients that need direct control rather than analysis-oriented workflows.

