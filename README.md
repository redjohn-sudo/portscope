# portscope

A TCP port scanner, written in C, that speaks the [Model Context Protocol](https://modelcontextprotocol.io).
One small binary: run it by hand, or let any MCP client (root-harness, Claude
Code, Codex, ...) drive it as a tool.

It does a plain connect scan: for each port it opens a non-blocking socket,
waits for the connect with `select()`, and reads whatever the service greets
it with. No raw packets, no root. The same thing a browser or an ssh client
does, one port at a time.

> Use it only on hosts you are allowed to test, such as your own machines and
> local network. The MCP tool is **not** marked read-only, so a client asks
> before each scan.

## Build

Needs a C11 compiler and `make`. No system dependencies; the JSON library
([cJSON](https://github.com/DaveGamble/cJSON)) is vendored under `vendor/`.

```bash
make
```

This produces the `portscope` binary.

## Use it as an MCP server

Point an MCP client at the binary. In root-harness, add a local server whose
command is the path to `portscope`; it exposes one tool:

- **`scan_ports(host, from=1, to=1024)`** — scan a port range on one host and
  report the open ports with any banner.

With the Claude Code CLI:

```bash
claude mcp add portscope /absolute/path/to/portscope
```

The server implements `initialize`, `tools/list`, and `tools/call` over
newline-delimited JSON-RPC 2.0 on stdin/stdout.

## Use it by hand

The protocol is just lines of JSON. For a quick check:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_ports","arguments":{"host":"127.0.0.1","from":1,"to":1024}}}' \
  | ./portscope
```

## Layout

- `src/net.c` — the connect scan and the banner read.
- `src/main.c` — the MCP server loop and the `scan_ports` tool.
- `vendor/cJSON.*` — the JSON library (vendored, not my code).

## License

MIT.
