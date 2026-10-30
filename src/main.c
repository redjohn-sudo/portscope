/* portscope - an MCP server, written in C, that scans TCP ports.
 *
 * It speaks the Model Context Protocol over stdin/stdout: one JSON-RPC 2.0
 * message per line. Any MCP client (root-harness, Claude Code, Codex, ...)
 * can launch this binary and call its one tool, `scan_ports`.
 *
 * Only three methods matter: `initialize` (handshake), `tools/list` (here is
 * what I can do), and `tools/call` (do it). Notifications carry no id and get
 * no answer. Everything else gets a "method not found" error. */
#include "cJSON.h"
#include "net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PS_NAME     "portscope"
#define PS_VERSION  "0.1.0"
#define PS_PROTOCOL "2025-06-18"
#define PS_PORT_CAP 4096            /* most ports we scan (and report) at once */

/* Print one JSON-RPC message, on its own line, and flush. cJSON's unformatted
 * printer never emits a newline, which is exactly what the line protocol needs. */
static void emit(cJSON *msg)
{
    char *text = cJSON_PrintUnformatted(msg);
    if (text) {
        printf("%s\n", text);
        fflush(stdout);
        free(text);
    }
    cJSON_Delete(msg);
}

/* Wrap a result object as {jsonrpc, id, result:<result>} and send it. Takes
 * ownership of `result`. `id` is copied from the request (may be null). */
static void send_result(const cJSON *id, cJSON *result)
{
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "jsonrpc", "2.0");
    cJSON_AddItemToObject(msg, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    cJSON_AddItemToObject(msg, "result", result);
    emit(msg);
}

static void send_error(const cJSON *id, int code, const char *message)
{
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "jsonrpc", "2.0");
    cJSON_AddItemToObject(msg, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    cJSON *err = cJSON_AddObjectToObject(msg, "error");
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message);
    emit(msg);
}

/* A tool result is {content:[{type:"text", text}], isError}. */
static void send_tool_text(const cJSON *id, const char *text, int is_error)
{
    cJSON *result = cJSON_CreateObject();
    cJSON *content = cJSON_AddArrayToObject(result, "content");
    cJSON *block = cJSON_CreateObject();
    cJSON_AddStringToObject(block, "type", "text");
    cJSON_AddStringToObject(block, "text", text);
    cJSON_AddItemToArray(content, block);
    cJSON_AddBoolToObject(result, "isError", is_error);
    send_result(id, result);
}

static void handle_initialize(const cJSON *id, const cJSON *params)
{
    const cJSON *pv = params ? cJSON_GetObjectItem(params, "protocolVersion") : NULL;
    const char *version = (pv && cJSON_IsString(pv)) ? pv->valuestring : PS_PROTOCOL;

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "protocolVersion", version);
    cJSON *caps = cJSON_AddObjectToObject(result, "capabilities");
    cJSON_AddItemToObject(caps, "tools", cJSON_CreateObject());
    cJSON *info = cJSON_AddObjectToObject(result, "serverInfo");
    cJSON_AddStringToObject(info, "name", PS_NAME);
    cJSON_AddStringToObject(info, "version", PS_VERSION);
    send_result(id, result);
}

static void handle_tools_list(const cJSON *id)
{
    cJSON *result = cJSON_CreateObject();
    cJSON *tools = cJSON_AddArrayToObject(result, "tools");

    cJSON *tool = cJSON_CreateObject();
    cJSON_AddStringToObject(tool, "name", "scan_ports");
    cJSON_AddStringToObject(tool, "description",
        "Scan a range of TCP ports on one host and report which are open, with "
        "any banner the service sends. Use only on hosts you are allowed to test.");

    cJSON *schema = cJSON_AddObjectToObject(tool, "inputSchema");
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *host = cJSON_AddObjectToObject(props, "host");
    cJSON_AddStringToObject(host, "type", "string");
    cJSON_AddStringToObject(host, "description", "Host name or IP address to scan.");
    cJSON *from = cJSON_AddObjectToObject(props, "from");
    cJSON_AddStringToObject(from, "type", "integer");
    cJSON_AddStringToObject(from, "description", "First port (default 1).");
    cJSON *to = cJSON_AddObjectToObject(props, "to");
    cJSON_AddStringToObject(to, "type", "integer");
    cJSON_AddStringToObject(to, "description", "Last port (default 1024).");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("host"));

    cJSON_AddItemToArray(tools, tool);
    send_result(id, result);
}

/* Read an integer argument that a client may send as a number or a string. */
static int arg_int(const cJSON *args, const char *key, int fallback)
{
    const cJSON *v = cJSON_GetObjectItem(args, key);
    if (!v) return fallback;
    if (cJSON_IsNumber(v)) return v->valueint;
    if (cJSON_IsString(v) && v->valuestring) return atoi(v->valuestring);
    return fallback;
}

static void handle_scan(const cJSON *id, const cJSON *args)
{
    const cJSON *host = args ? cJSON_GetObjectItem(args, "host") : NULL;
    if (!host || !cJSON_IsString(host) || host->valuestring[0] == '\0') {
        send_tool_text(id, "scan_ports needs a 'host' (name or IP).", 1);
        return;
    }
    int from = arg_int(args, "from", 1);
    int to   = arg_int(args, "to", 1024);
    if (from < 1) from = 1;
    if (to > 65535) to = 65535;
    if (to < from) to = from;
    if (to - from + 1 > PS_PORT_CAP) to = from + PS_PORT_CAP - 1;

    ps_result *results = calloc(PS_PORT_CAP, sizeof(ps_result));
    if (!results) {
        send_tool_text(id, "out of memory", 1);
        return;
    }
    int count = 0;
    int rc = ps_scan(host->valuestring, from, to, 400, results, PS_PORT_CAP, &count);
    if (rc != 0) {
        char msg[320];
        snprintf(msg, sizeof(msg), "Could not resolve host '%s'.", host->valuestring);
        send_tool_text(id, msg, 1);
        free(results);
        return;
    }

    /* Build the human-readable report into a growing buffer. */
    size_t cap = 256 + (size_t)count * (PS_BANNER_MAX + 32);
    char *text = malloc(cap);
    if (!text) { send_tool_text(id, "out of memory", 1); free(results); return; }
    int n = snprintf(text, cap, "Scan of %s ports %d-%d: %d open.\n",
                     host->valuestring, from, to, count);
    for (int i = 0; i < count && n > 0 && (size_t)n < cap; i++) {
        n += snprintf(text + n, cap - (size_t)n, "  %-6d open   %s\n",
                      results[i].port,
                      results[i].banner[0] ? results[i].banner : "(no banner)");
    }
    if (count == 0)
        snprintf(text, cap, "No open ports on %s in range %d-%d.", host->valuestring, from, to);

    send_tool_text(id, text, 0);
    free(text);
    free(results);
}

static void handle_tools_call(const cJSON *id, const cJSON *params)
{
    const cJSON *name = params ? cJSON_GetObjectItem(params, "name") : NULL;
    const cJSON *args = params ? cJSON_GetObjectItem(params, "arguments") : NULL;
    if (name && cJSON_IsString(name) && strcmp(name->valuestring, "scan_ports") == 0) {
        handle_scan(id, args);
    } else {
        send_tool_text(id, "Unknown tool. This server offers only 'scan_ports'.", 1);
    }
}

static void dispatch(cJSON *req)
{
    const cJSON *method = cJSON_GetObjectItem(req, "method");
    const cJSON *id     = cJSON_GetObjectItem(req, "id");   /* absent => notification */
    const cJSON *params = cJSON_GetObjectItem(req, "params");
    if (!method || !cJSON_IsString(method)) return;

    const char *m = method->valuestring;
    if (strcmp(m, "initialize") == 0)        handle_initialize(id, params);
    else if (strcmp(m, "tools/list") == 0)   handle_tools_list(id);
    else if (strcmp(m, "tools/call") == 0)   handle_tools_call(id, params);
    else if (strcmp(m, "ping") == 0)         send_result(id, cJSON_CreateObject());
    else if (id)                             send_error(id, -32601, "method not found");
    /* notifications (no id), e.g. notifications/initialized: nothing to send */
}

int main(void)
{
    char   *line = NULL;
    size_t  cap  = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, stdin)) != -1) {
        if (len == 0 || line[0] == '\n') continue;
        cJSON *req = cJSON_Parse(line);
        if (!req) continue;                 /* skip anything that is not JSON */
        dispatch(req);
        cJSON_Delete(req);
    }
    free(line);
    return 0;
}
