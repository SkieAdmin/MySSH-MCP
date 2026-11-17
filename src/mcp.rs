//! MCP (JSON-RPC 2.0) protocol handling, shared by the HTTP and stdio transports.

use crate::audit::{q, Kind};
use crate::state::AppState;
use crate::tools;
use serde_json::{json, Value};

pub const SUPPORTED_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
pub const LATEST_VERSION: &str = "2025-11-25";

const INSTRUCTIONS: &str = "MySSH-MCP gives you guarded ROOT access to a Linux server.\n\
1. Commands run as root, non-interactively (no TTY, no stdin): always use -y / --no-pager / non-interactive flags.\n\
2. A safety policy blocks destructive and lock-out actions (wiping system paths, disk formatting, stopping SSH, \
firewall flushes, curl|bash, obfuscated commands, touching MySSH-MCP's own files, dropping databases...). \
Denied calls return '⛔ DENIED' and are logged together with every other command in /server_log/claude_log.txt. \
Never try to bypass a denial (encoding, scripts, other tools) — explain the situation to the user instead.\n\
3. Inspect before you change. Validate configs before reloading (nginx -t, sshd -t, docker compose config). \
write_file backs files up automatically to /var/backups/myssh-mcp.\n\
4. Databases: make every change with database_query (never mysql/psql via execute_command). It backs the database up \
before any data-changing query and returns a backup id; if something goes wrong, revert with database_restore \
(list backups with database_backups). Tell the user the backup id after changing data.\n\
5. Use systemd units or `nohup ... &` for long-running processes; use timeout_secs for slow commands.";

fn error(id: Value, code: i64, msg: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })
}

fn result(id: Value, r: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": r })
}

pub fn parse_error(detail: &str) -> Value {
    error(Value::Null, -32700, &format!("Parse error: {detail}"))
}

/// Handle one JSON-RPC message. Returns None for notifications and client responses.
pub async fn handle(st: &AppState, msg: Value, client: &str) -> Option<Value> {
    let Some(obj) = msg.as_object() else {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    };
    let id = obj.get("id").cloned();
    let Some(method) = obj.get("method").and_then(|m| m.as_str()) else {
        let is_response = obj.contains_key("result") || obj.contains_key("error");
        return if is_response { None } else { Some(error(id.unwrap_or(Value::Null), -32600, "Invalid Request")) };
    };
    // Notifications (no id) never get a response.
    let id = id?;
    let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));

    let resp = match method {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or(LATEST_VERSION);
            let version = if SUPPORTED_VERSIONS.contains(&requested) { requested } else { LATEST_VERSION };
            let name = params.pointer("/clientInfo/name").and_then(|v| v.as_str()).unwrap_or("?");
            let ver = params.pointer("/clientInfo/version").and_then(|v| v.as_str()).unwrap_or("?");
            st.audit.log(
                Kind::System,
                client,
                "",
                &format!("msg=\"client initialized\" client_name={} client_version={} protocol={version}", q(name), q(ver)),
            );
            result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": {
                        "name": "MySSH-MCP",
                        "title": "MySSH-MCP (guarded root shell)",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": INSTRUCTIONS
                }),
            )
        }
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({ "tools": tools::definitions() })),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(|v| v.as_str()) else {
                return Some(error(id, -32602, "Invalid params: missing tool name"));
            };
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let out = tools::call(st, name, &args, client).await;
            result(id, json!({ "content": [{ "type": "text", "text": out.text }], "isError": out.is_error }))
        }
        "resources/list" => result(id, json!({ "resources": [] })),
        "resources/templates/list" => result(id, json!({ "resourceTemplates": [] })),
        "prompts/list" => result(id, json!({ "prompts": [] })),
        "logging/setLevel" => result(id, json!({})),
        other => error(id, -32601, &format!("Method not found: {other}")),
    };
    Some(resp)
}

/// Handle a request body: a single message or a JSON-RPC batch.
pub async fn handle_body(st: &AppState, body: Value, client: &str) -> Option<Value> {
    match body {
        Value::Array(items) => {
            if items.is_empty() {
                return Some(error(Value::Null, -32600, "Invalid Request: empty batch"));
            }
            let mut out = Vec::new();
            for m in items {
                if let Some(r) = handle(st, m, client).await {
                    out.push(r);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(Value::Array(out))
            }
        }
        other => handle(st, other, client).await,
    }
}
