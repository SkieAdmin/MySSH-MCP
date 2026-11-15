//! MCP tools exposed to the AI. Every tool call is policy-checked and audit-logged.

mod db;
mod fs;
mod system;

use crate::audit::{q, Kind};
use crate::exec::{self, ExecSpec};
use crate::state::AppState;
use serde_json::{json, Value};
use std::time::Duration;

pub struct ToolOutput {
    pub text: String,
    pub is_error: bool,
}

impl ToolOutput {
    pub fn ok(text: impl Into<String>) -> Self {
        Self { text: text.into(), is_error: false }
    }
    pub fn err(text: impl Into<String>) -> Self {
        Self { text: text.into(), is_error: true }
    }
}

pub(crate) fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

pub(crate) fn arg_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
}

pub(crate) fn arg_bool(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(|v| v.as_bool().or_else(|| v.as_str().map(|s| s.eq_ignore_ascii_case("true"))))
}

pub(crate) fn timeout_from(st: &AppState, args: &Value) -> Duration {
    let l = &st.cfg.limits;
    let secs = arg_u64(args, "timeout_secs").unwrap_or(l.default_timeout_secs);
    Duration::from_secs(secs.clamp(1, l.max_timeout_secs.max(1)))
}

/// Working directory for spawned processes: the configured default if it exists, else `/`.
pub(crate) fn default_cwd(st: &AppState) -> String {
    let d = &st.cfg.limits.default_cwd;
    if std::path::Path::new(d).is_dir() {
        d.clone()
    } else {
        "/".into()
    }
}

/// Log a policy denial and build the message returned to the AI.
pub(crate) fn denied(st: &AppState, client: &str, tool: &str, what: &str, reason: &str) -> ToolOutput {
    st.audit.log(Kind::Denied, client, tool, &format!("{what} reason={}", q(reason)));
    ToolOutput::err(format!(
        "⛔ DENIED by the MySSH-MCP safety policy\nReason: {reason}\n\n\
         This attempt has been logged. Do not try to work around this rule (obfuscation, other tools, \
         scripts). If the operation is genuinely required, explain it to the user so the server owner can \
         run it manually or adjust /etc/myssh-mcp/config.toml."
    ))
}

/// Run a granted process, log the RESULT line and render the output for the AI.
pub(crate) async fn run_logged(
    st: &AppState,
    client: &str,
    tool: &str,
    spec: ExecSpec,
    nonzero_is_error: bool,
) -> ToolOutput {
    let _permit = match st.sem.acquire().await {
        Ok(p) => p,
        Err(_) => return ToolOutput::err("server is shutting down"),
    };
    match exec::run(spec).await {
        Ok(out) => {
            let exit = out.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".into());
            st.audit.log(
                Kind::Result,
                client,
                tool,
                &format!(
                    "exit={exit} signal={} duration_ms={} timed_out={} truncated={} stdout_bytes={} stderr_bytes={}",
                    out.signal.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                    out.duration_ms,
                    out.timed_out,
                    out.truncated,
                    out.stdout.len(),
                    out.stderr.len()
                ),
            );
            let is_error = out.timed_out || (nonzero_is_error && !out.success());
            ToolOutput { text: out.render(), is_error }
        }
        Err(e) => {
            st.audit.log(Kind::Error, client, tool, &format!("error={}", q(&e)));
            ToolOutput::err(e)
        }
    }
}

pub async fn call(st: &AppState, name: &str, args: &Value, client: &str) -> ToolOutput {
    let empty = json!({});
    let args = if args.is_object() { args } else { &empty };
    match name {
        "execute_command" => execute_command(st, args, client).await,
        "read_file" => fs::read_file(st, args, client).await,
        "write_file" => fs::write_file(st, args, client).await,
        "list_directory" => fs::list_directory(st, args, client).await,
        "system_info" => system::system_info(st, client).await,
        "service_control" => system::service_control(st, args, client).await,
        "docker" => db::docker(st, args, client).await,
        "database_query" => db::database_query(st, args, client).await,
        other => {
            st.audit.log(Kind::Error, client, other, "msg=\"unknown tool\"");
            ToolOutput::err(format!("unknown tool `{other}`"))
        }
    }
}

async fn execute_command(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "execute_command";
    let Some(cmd) = arg_str(args, "command") else {
        return ToolOutput::err("missing required argument `command`");
    };
    if cmd.len() > 100_000 {
        return ToolOutput::err("command is too long (max 100000 bytes) — write a script with write_file instead");
    }
    let cwd = arg_str(args, "cwd").map(String::from).unwrap_or_else(|| default_cwd(st));
    let what = format!("cmd={} cwd={}", q(cmd), q(&cwd));
    if !cwd.starts_with('/') {
        return ToolOutput::err("`cwd` must be an absolute path");
    }
    if let Err(reason) = st.policy.check_command(cmd, &cwd) {
        return denied(st, client, TOOL, &what, &reason);
    }
    if !std::path::Path::new(&cwd).is_dir() {
        return ToolOutput::err(format!("working directory `{cwd}` does not exist"));
    }
    let timeout = timeout_from(st, args);
    st.audit.log(Kind::Granted, client, TOOL, &format!("{what} timeout={}s", timeout.as_secs()));
    let spec = ExecSpec {
        program: "/bin/bash".into(),
        args: vec!["-c".into(), cmd.to_string()],
        cwd: Some(cwd),
        env: Vec::new(),
        stdin: None,
        timeout,
        max_output: st.cfg.limits.max_output_bytes,
    };
    run_logged(st, client, TOOL, spec, true).await
}

/// JSON schemas of all tools for `tools/list`.
pub fn definitions() -> Value {
    json!([
        {
            "name": "execute_command",
            "title": "Execute shell command (root)",
            "description": "Run a shell command on the Linux server as root via `bash -c` (non-interactive: no TTY, no stdin — always pass flags like -y / --no-pager). Every command is checked by the MySSH-MCP safety policy first: destructive operations (rm -rf on system paths, disk formatting, lock-outs, stopping SSH, firewall flushes, curl|bash, obfuscated commands, touching MySSH-MCP's own files, ...) are DENIED and logged. Output is capped; use timeout_secs for long jobs and `nohup ... &` / systemd-run for background services.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "Shell command line, e.g. `apt-get install -y nginx` or `cd /opt/app && git pull`" },
                    "cwd": { "type": "string", "description": "Absolute working directory (default /root)" },
                    "timeout_secs": { "type": "integer", "minimum": 1, "description": "Timeout in seconds (default 120, max 1800)" }
                },
                "required": ["command"]
            },
            "annotations": { "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "read_file",
            "title": "Read file",
            "description": "Read a text file from the server (absolute path). Use tail_lines to read only the end of big log files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path" },
                    "max_bytes": { "type": "integer", "minimum": 1, "description": "Maximum bytes to return (default/max 1 MiB)" },
                    "tail_lines": { "type": "integer", "minimum": 1, "description": "Only return the last N lines" }
                },
                "required": ["path"]
            },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "write_file",
            "title": "Write file",
            "description": "Create, overwrite or append to a file (absolute path). An existing file is backed up to /var/backups/myssh-mcp before it is overwritten. Critical files (/etc/passwd, /etc/shadow, sudoers, sshd_config, authorized_keys, /boot, system binaries, MySSH-MCP's own files) are protected.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path" },
                    "content": { "type": "string", "description": "File content (UTF-8 text)" },
                    "mode": { "type": "string", "enum": ["overwrite", "append"], "description": "Default: overwrite" },
                    "create_dirs": { "type": "boolean", "description": "Create missing parent directories (default false)" },
                    "backup": { "type": "boolean", "description": "Back up the existing file before overwriting (default true)" }
                },
                "required": ["path", "content"]
            },
            "annotations": { "destructiveHint": true }
        },
        {
            "name": "list_directory",
            "title": "List directory",
            "description": "List the entries of a directory with type, permissions, size and modification time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path" },
                    "show_hidden": { "type": "boolean", "description": "Include dot-files (default true)" }
                },
                "required": ["path"]
            },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "system_info",
            "title": "System overview",
            "description": "Overview of the server: OS, kernel, uptime, load, CPU, memory, disks, listening ports and running Docker containers.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "service_control",
            "title": "Manage systemd service",
            "description": "Manage a systemd service (status/start/stop/restart/reload/enable/disable/is-active/is-enabled) or read its journal (logs). SSH, networking, logging and MySSH-MCP itself cannot be stopped.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["status", "start", "stop", "restart", "reload", "enable", "disable", "is-active", "is-enabled", "logs"] },
                    "service": { "type": "string", "description": "Unit name, e.g. nginx or docker.service" },
                    "lines": { "type": "integer", "minimum": 1, "description": "For action=logs: number of journal lines (default 100)" }
                },
                "required": ["action", "service"]
            }
        },
        {
            "name": "docker",
            "title": "Docker CLI",
            "description": "Run the docker CLI with an argument list (no shell), e.g. [\"ps\",\"-a\"], [\"logs\",\"--tail\",\"100\",\"web\"], [\"compose\",\"-f\",\"/opt/app/compose.yml\",\"up\",\"-d\"], [\"exec\",\"db\",\"psql\",\"-U\",\"postgres\",\"-c\",\"select 1\"]. No TTY: never use -it. Volume deletion, system/container prune, compose down -v, --privileged and host-root bind mounts are blocked.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "args": { "type": "array", "items": { "type": "string" }, "description": "Arguments after `docker`" },
                    "timeout_secs": { "type": "integer", "minimum": 1, "description": "Timeout in seconds (default 120)" }
                },
                "required": ["args"]
            },
            "annotations": { "destructiveHint": true }
        },
        {
            "name": "database_query",
            "title": "Run SQL query",
            "description": "Run SQL against a local database using its CLI client. engine=mysql (MySQL/MariaDB; root via unix socket when no user is given), postgres (runs as the `postgres` system user when no user/host is given) or sqlite (needs `path`). DROP DATABASE/TABLE, TRUNCATE, DELETE/UPDATE without WHERE, COPY ... PROGRAM, INTO OUTFILE and shell escapes are blocked.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "engine": { "type": "string", "enum": ["mysql", "mariadb", "postgres", "sqlite"] },
                    "query": { "type": "string", "description": "SQL statement(s)" },
                    "database": { "type": "string", "description": "Database name" },
                    "user": { "type": "string" },
                    "password": { "type": "string" },
                    "host": { "type": "string" },
                    "port": { "type": "integer" },
                    "path": { "type": "string", "description": "SQLite database file (absolute path)" },
                    "timeout_secs": { "type": "integer", "minimum": 1 }
                },
                "required": ["engine", "query"]
            },
            "annotations": { "destructiveHint": true }
        }
    ])
}
