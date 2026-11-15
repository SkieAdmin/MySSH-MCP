//! docker / database_query

use super::{arg_str, arg_u64, default_cwd, denied, run_logged, timeout_from, ToolOutput};
use crate::audit::{q, Kind};
use crate::exec::{self, ExecSpec};
use crate::policy::shell_quote;
use crate::state::AppState;
use serde_json::Value;

pub async fn docker(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "docker";
    let Some(arr) = args.get("args").and_then(|v| v.as_array()) else {
        return ToolOutput::err("`args` must be an array of strings, e.g. [\"ps\", \"-a\"]");
    };
    let mut argv = Vec::with_capacity(arr.len());
    for v in arr {
        match v.as_str() {
            Some(s) => argv.push(s.to_string()),
            None => return ToolOutput::err("every element of `args` must be a string"),
        }
    }
    if argv.is_empty() {
        return ToolOutput::err("`args` is empty");
    }
    let display = format!("docker {}", argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" "));
    let what = format!("cmd={}", q(&display));
    let cwd = default_cwd(st);
    if let Err(reason) = st.policy.check_command(&display, &cwd) {
        return denied(st, client, TOOL, &what, &reason);
    }
    if !exec::which("docker") {
        return ToolOutput::err("docker is not installed on this server");
    }
    let timeout = timeout_from(st, args);
    st.audit.log(Kind::Granted, client, TOOL, &format!("{what} timeout={}s", timeout.as_secs()));
    let spec = ExecSpec {
        program: "docker".into(),
        args: argv,
        cwd: Some(cwd),
        env: Vec::new(),
        stdin: None,
        timeout,
        max_output: st.cfg.limits.max_output_bytes,
    };
    run_logged(st, client, TOOL, spec, true).await
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.@:%-/".contains(c))
}

pub async fn database_query(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "database_query";
    let (Some(engine), Some(query)) = (arg_str(args, "engine"), arg_str(args, "query")) else {
        return ToolOutput::err("missing required arguments `engine` and `query`");
    };
    let database = arg_str(args, "database");
    let user = arg_str(args, "user");
    let host = arg_str(args, "host");
    let password = arg_str(args, "password");
    let port = arg_u64(args, "port").map(|p| p.to_string());
    for (name, v) in [("database", database), ("user", user), ("host", host)] {
        if let Some(v) = v {
            if !valid_ident(v) {
                return ToolOutput::err(format!("invalid `{name}`"));
            }
        }
    }
    let what = format!(
        "engine={engine} database={} user={} host={} query={}",
        q(database.unwrap_or("")),
        q(user.unwrap_or("")),
        q(host.unwrap_or("")),
        q(query)
    );
    if let Err(reason) = st.policy.check_sql(query) {
        return denied(st, client, TOOL, &what, &reason);
    }

    let mut env: Vec<(String, String)> = Vec::new();
    let mut cwd = "/tmp".to_string();
    let (program, argv): (String, Vec<String>) = match engine {
        "mysql" | "mariadb" => {
            let prog = if exec::which("mysql") { "mysql" } else { "mariadb" };
            let mut a = vec!["--table".to_string(), "--default-character-set=utf8mb4".to_string()];
            if let Some(u) = user {
                a.push(format!("--user={u}"));
            }
            if let Some(h) = host {
                a.push(format!("--host={h}"));
            }
            if let Some(p) = &port {
                a.push(format!("--port={p}"));
            }
            if let Some(pw) = password {
                env.push(("MYSQL_PWD".into(), pw.into()));
            }
            if let Some(d) = database {
                a.push(d.to_string());
            }
            (prog.to_string(), a)
        }
        "postgres" | "postgresql" => {
            let base = vec!["-X", "-v", "ON_ERROR_STOP=1", "-P", "pager=off"];
            let mut a: Vec<String> = Vec::new();
            let peer = user.is_none() && host.is_none() && password.is_none();
            let prog = if peer {
                a.extend(["-u", "postgres", "--", "psql"].iter().map(|s| s.to_string()));
                "runuser"
            } else {
                "psql"
            };
            a.extend(base.iter().map(|s| s.to_string()));
            if let Some(h) = host {
                a.push(format!("--host={h}"));
            }
            if let Some(p) = &port {
                a.push(format!("--port={p}"));
            }
            if let Some(u) = user {
                a.push(format!("--username={u}"));
            }
            if let Some(d) = database {
                a.push(format!("--dbname={d}"));
            }
            if let Some(pw) = password {
                env.push(("PGPASSWORD".into(), pw.into()));
            }
            (prog.to_string(), a)
        }
        "sqlite" | "sqlite3" => {
            let Some(path) = arg_str(args, "path") else {
                return ToolOutput::err("sqlite needs `path` (absolute path of the database file)");
            };
            if let Err(reason) = st.policy.check_write_path(path) {
                return denied(st, client, TOOL, &format!("{what} path={}", q(path)), &reason);
            }
            if let Some(parent) = std::path::Path::new(path).parent() {
                cwd = parent.to_string_lossy().into_owned();
            }
            ("sqlite3".to_string(), vec!["-header".into(), "-column".into(), path.to_string()])
        }
        other => return ToolOutput::err(format!("unsupported engine `{other}` (use mysql, postgres or sqlite)")),
    };
    let client_bin = if program == "runuser" { "psql" } else { program.as_str() };
    if !exec::which(client_bin) {
        return ToolOutput::err(format!("`{client_bin}` client is not installed on this server"));
    }
    if !std::path::Path::new(&cwd).is_dir() {
        cwd = "/".into();
    }
    let timeout = timeout_from(st, args);
    st.audit.log(Kind::Granted, client, TOOL, &format!("{what} timeout={}s", timeout.as_secs()));
    let mut input = query.to_string();
    if !input.ends_with('\n') {
        input.push('\n');
    }
    let spec = ExecSpec {
        program,
        args: argv,
        cwd: Some(cwd),
        env,
        stdin: Some(input.into_bytes()),
        timeout,
        max_output: st.cfg.limits.max_output_bytes,
    };
    run_logged(st, client, TOOL, spec, true).await
}
