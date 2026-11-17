//! docker, database_query, database_backup, database_backups, database_restore

use super::dbbackup;
use super::{arg_bool, arg_str, arg_u64, default_cwd, denied, run_logged, timeout_from, ToolOutput};
use crate::audit::{q, Kind};
use crate::exec::{self, ExecSpec};
use crate::policy::{self, shell_quote};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

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

pub(crate) fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.@:%-/".contains(c))
}

// ------------------------------------------------------------------------ database target

/// Which client program of an engine to run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Client,
    Dump,
    Restore,
    CreateDb,
}

/// Where a database lives and how to connect to it (the password is never stored).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbTarget {
    /// mysql | postgres | sqlite
    pub engine: String,
    pub database: Option<String>,
    pub user: Option<String>,
    pub host: Option<String>,
    pub port: Option<u64>,
    /// Docker container running the database (commands go through `docker exec -i`).
    pub container: Option<String>,
    /// SQLite database file.
    pub path: Option<String>,
    #[serde(skip)]
    pub password: Option<String>,
}

impl DbTarget {
    pub fn from_args(args: &Value) -> Result<DbTarget, String> {
        let engine = match arg_str(args, "engine").unwrap_or("").trim() {
            "mysql" | "mariadb" => "mysql",
            "postgres" | "postgresql" | "pg" => "postgres",
            "sqlite" | "sqlite3" => "sqlite",
            "" => return Err("missing required argument `engine` (mysql, postgres or sqlite)".into()),
            other => return Err(format!("unsupported engine `{other}` (use mysql, postgres or sqlite)")),
        };
        let s = |k: &str| arg_str(args, k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let t = DbTarget {
            engine: engine.to_string(),
            database: s("database"),
            user: s("user"),
            host: s("host"),
            port: arg_u64(args, "port"),
            container: s("container"),
            path: s("path"),
            password: arg_str(args, "password").map(String::from),
        };
        t.validate()?;
        Ok(t)
    }

    pub fn validate(&self) -> Result<(), String> {
        let fields = [
            ("database", &self.database),
            ("user", &self.user),
            ("host", &self.host),
            ("container", &self.container),
        ];
        for (name, v) in fields {
            if let Some(v) = v {
                if !valid_ident(v) {
                    return Err(format!("invalid `{name}`"));
                }
            }
        }
        if self.engine == "sqlite" {
            if !self.path.as_deref().map(|p| p.starts_with('/')).unwrap_or(false) {
                return Err("sqlite needs `path` (absolute path of the database file)".into());
            }
            if self.container.is_some() {
                return Err("`container` is not supported for sqlite".into());
            }
        }
        Ok(())
    }

    /// Local PostgreSQL reached as the `postgres` system user (peer authentication).
    fn peer(&self) -> bool {
        self.engine == "postgres"
            && self.container.is_none()
            && self.user.is_none()
            && self.host.is_none()
            && self.password.is_none()
    }

    /// Database the connection lands in when no other is named.
    pub fn effective_db(&self) -> Option<String> {
        match self.engine.as_str() {
            "postgres" => Some(
                self.database
                    .clone()
                    .or_else(|| self.user.clone())
                    .unwrap_or_else(|| "postgres".into()),
            ),
            "sqlite" => self.path.clone(),
            _ => self.database.clone(),
        }
    }

    /// Key identifying one database, used to reuse recent backups.
    pub fn key(&self, db: Option<&str>) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.engine,
            self.container.as_deref().unwrap_or("local"),
            self.host.as_deref().unwrap_or(""),
            self.port.map(|p| p.to_string()).unwrap_or_default(),
            db.unwrap_or("*")
        )
    }

    pub fn describe(&self) -> String {
        let base = match self.engine.as_str() {
            "sqlite" => format!("sqlite {}", self.path.as_deref().unwrap_or("?")),
            e => format!("{e} database `{}`", self.effective_db().unwrap_or_else(|| "(all)".into())),
        };
        match (&self.container, &self.host) {
            (Some(c), _) => format!("{base} in container `{c}`"),
            (None, Some(h)) => format!("{base} on {h}"),
            _ => base,
        }
    }

    fn pw_var(&self) -> &'static str {
        if self.engine == "mysql" {
            "MYSQL_PWD"
        } else {
            "PGPASSWORD"
        }
    }

    /// argv running `tool` against this target, wrapped in `docker exec -i` / `runuser` as needed.
    /// The password travels in an environment variable, never on the command line.
    pub fn argv(&self, tool: Tool, extra: &[String], env: &mut Vec<(String, String)>) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        if let Some(pw) = &self.password {
            env.push((self.pw_var().to_string(), pw.clone()));
        }
        let in_container = self.container.is_some();
        if let Some(c) = &self.container {
            a.extend(["docker", "exec", "-i"].iter().map(|s| s.to_string()));
            if self.password.is_some() {
                a.push("-e".into());
                a.push(self.pw_var().into());
            }
            a.push(c.clone());
        } else if self.peer() {
            a.extend(["runuser", "-u", "postgres", "--"].iter().map(|s| s.to_string()));
        }
        match self.engine.as_str() {
            "mysql" => {
                let (primary, fallback) = match tool {
                    Tool::Dump => ("mysqldump", "mariadb-dump"),
                    _ => ("mysql", "mariadb"),
                };
                if in_container {
                    a.push("sh".into());
                    a.push("-c".into());
                    a.push(format!(
                        "if command -v {primary} >/dev/null 2>&1; then exec {primary} \"$@\"; else exec {fallback} \"$@\"; fi"
                    ));
                    a.push("sh".into());
                } else {
                    let program = if exec::which(primary) { primary } else { fallback };
                    a.push(program.to_string());
                }
                match &self.user {
                    Some(u) => a.push(format!("--user={u}")),
                    None if in_container => a.push("--user=root".into()),
                    None => {}
                }
                if let Some(h) = &self.host {
                    a.push(format!("--host={h}"));
                }
                if let Some(p) = self.port {
                    a.push(format!("--port={p}"));
                }
            }
            "postgres" => {
                let program = match tool {
                    Tool::Client => "psql",
                    Tool::Dump => "pg_dump",
                    Tool::Restore => "pg_restore",
                    Tool::CreateDb => "createdb",
                };
                a.push(program.into());
                if let Some(h) = &self.host {
                    a.push(format!("--host={h}"));
                }
                if let Some(p) = self.port {
                    a.push(format!("--port={p}"));
                }
                match &self.user {
                    Some(u) => a.push(format!("--username={u}")),
                    None if in_container => a.push("--username=postgres".into()),
                    None => {}
                }
            }
            _ => a.push("sqlite3".into()),
        }
        a.extend(extra.iter().cloned());
        a
    }
}

/// The host binary that must exist for `argv` to run.
pub(crate) fn missing_binary(argv: &[String]) -> Option<String> {
    let bin = if argv.first().map(|s| s.as_str()) == Some("runuser") { argv.get(4) } else { argv.first() }?;
    if exec::which(bin) {
        None
    } else {
        Some(bin.clone())
    }
}

fn short(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let mut t: String = flat.chars().take(max).collect();
        t.push('…');
        t
    }
}

/// Database that has to be backed up before `query` runs.
fn backup_db_for(t: &DbTarget, query: &str) -> Option<String> {
    if t.engine != "sqlite" {
        if let Some(d) = policy::dropped_database(query) {
            if valid_ident(&d) {
                return Some(d);
            }
        }
    }
    t.effective_db()
}

fn restore_hint(id: &str) -> String {
    format!("revert with database_restore {{\"backup_id\": \"{id}\"}}")
}

// ------------------------------------------------------------------------ tools

pub async fn database_query(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "database_query";
    let t = match DbTarget::from_args(args) {
        Ok(t) => t,
        Err(e) => return ToolOutput::err(e),
    };
    let Some(query) = arg_str(args, "query") else {
        return ToolOutput::err("missing required argument `query`");
    };
    let what = format!("target={} query={}", q(&t.describe()), q(query));
    if let Err(reason) = st.policy.check_sql_hard(query) {
        return denied(st, client, TOOL, &what, &reason);
    }
    if let Some(p) = &t.path {
        if let Err(reason) = st.policy.check_write_path(p) {
            return denied(st, client, TOOL, &what, &reason);
        }
    }

    let read_only = policy::sql_is_read_only(query);
    let destructive = policy::sql_destructive(query);
    let dbc = &st.cfg.database;
    let mut notes: Vec<String> = Vec::new();
    let mut backup_id: Option<String> = None;

    if !read_only && dbc.backup_before_write {
        let db = backup_db_for(&t, query);
        let key = t.key(db.as_deref());
        let recent = if destructive.is_none() && dbc.reuse_backup_within_secs > 0 {
            st.db_last_backup
                .lock()
                .ok()
                .and_then(|m| m.get(&key).cloned())
                .filter(|(when, _)| when.elapsed().as_secs() <= dbc.reuse_backup_within_secs)
        } else {
            None
        };
        match recent {
            Some((when, id)) => {
                notes.push(format!(
                    "🛟 Using backup `{id}` taken {}s ago (covers this change) — {}",
                    when.elapsed().as_secs(),
                    restore_hint(&id)
                ));
                backup_id = Some(id);
            }
            None => {
                let reason = format!("before query: {}", short(query, 300));
                match dbbackup::create(st, &t, db, &reason, client).await {
                    Ok(m) => {
                        if let Ok(mut map) = st.db_last_backup.lock() {
                            map.insert(key, (Instant::now(), m.id.clone()));
                        }
                        notes.push(format!(
                            "🛟 Backup `{}` ({}) taken before this change — {}",
                            m.id,
                            dbbackup::human_size(m.size_bytes),
                            restore_hint(&m.id)
                        ));
                        backup_id = Some(m.id);
                    }
                    Err(e) => {
                        if dbc.require_backup || destructive.is_some() {
                            return denied(
                                st,
                                client,
                                TOOL,
                                &what,
                                &format!("the automatic backup failed, so the change was NOT executed: {e}"),
                            );
                        }
                        notes.push(format!("⚠ automatic backup failed ({e}); continuing because require_backup = false"));
                    }
                }
            }
        }
    }

    if let Some(reason) = &destructive {
        let allowed =
            st.cfg.policy.allow_destructive_sql || (dbc.allow_destructive_with_backup && backup_id.is_some());
        if !allowed {
            return denied(
                st,
                client,
                TOOL,
                &what,
                &format!("{reason} — blocked because no backup could be taken first (see [database] in config.toml)"),
            );
        }
    }

    let mut env = Vec::new();
    let extra: Vec<String> = match t.engine.as_str() {
        "mysql" => {
            let mut e = vec!["--table".to_string(), "--default-character-set=utf8mb4".to_string()];
            e.extend(t.database.clone());
            e
        }
        "postgres" => {
            let mut e: Vec<String> =
                ["-X", "-v", "ON_ERROR_STOP=1", "-P", "pager=off"].iter().map(|s| s.to_string()).collect();
            if let Some(d) = &t.database {
                e.push(format!("--dbname={d}"));
            }
            e
        }
        _ => vec!["-header".into(), "-column".into(), t.path.clone().unwrap_or_default()],
    };
    let argv = t.argv(Tool::Client, &extra, &mut env);
    if let Some(bin) = missing_binary(&argv) {
        return ToolOutput::err(format!("`{bin}` is not installed on this server"));
    }
    let timeout = timeout_from(st, args);
    st.audit.log(
        Kind::Granted,
        client,
        TOOL,
        &format!("{what} backup={} timeout={}s", backup_id.as_deref().unwrap_or("-"), timeout.as_secs()),
    );
    let mut input = query.to_string();
    if !input.ends_with('\n') {
        input.push('\n');
    }
    let spec = ExecSpec {
        program: argv[0].clone(),
        args: argv[1..].to_vec(),
        cwd: Some("/tmp".into()),
        env,
        stdin: Some(input.into_bytes()),
        timeout,
        max_output: st.cfg.limits.max_output_bytes,
    };
    let mut out = run_logged(st, client, TOOL, spec, true).await;
    if !notes.is_empty() {
        out.text = format!("{}\n\n{}", notes.join("\n"), out.text);
    }
    out
}

pub async fn database_backup(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "database_backup";
    let t = match DbTarget::from_args(args) {
        Ok(t) => t,
        Err(e) => return ToolOutput::err(e),
    };
    st.audit.log(Kind::Granted, client, TOOL, &format!("target={}", q(&t.describe())));
    let db = t.effective_db();
    match dbbackup::create(st, &t, db, "manual backup", client).await {
        Ok(m) => ToolOutput::ok(format!(
            "Backup created\n  id   : {}\n  of   : {}\n  file : {}\n  size : {}\nTo {}",
            m.id,
            m.target.describe(),
            m.file,
            dbbackup::human_size(m.size_bytes),
            restore_hint(&m.id)
        )),
        Err(e) => ToolOutput::err(format!("backup failed: {e}")),
    }
}

pub async fn database_backups(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    st.audit.log(Kind::Granted, client, "database_backups", "msg=\"list backups\"");
    let engine = arg_str(args, "engine");
    let database = arg_str(args, "database");
    let all = dbbackup::list();
    let rows: Vec<String> = all
        .iter()
        .filter(|m| engine.map(|e| m.target.engine == e || (e == "mariadb" && m.target.engine == "mysql")).unwrap_or(true))
        .filter(|m| database.map(|d| m.database.as_deref() == Some(d)).unwrap_or(true))
        .take(50)
        .map(|m| {
            format!(
                "{}\n    {} | {} | {} | {}",
                m.id,
                m.created,
                m.target.describe(),
                dbbackup::human_size(m.size_bytes),
                short(&m.reason, 120)
            )
        })
        .collect();
    if rows.is_empty() {
        return ToolOutput::ok("No database backups found.");
    }
    ToolOutput::ok(format!(
        "Database backups (newest first, {} total):\n{}\n\nRestore one with database_restore {{\"backup_id\": \"<id>\"}}",
        all.len(),
        rows.join("\n")
    ))
}

pub async fn database_restore(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "database_restore";
    let Some(id) = arg_str(args, "backup_id") else {
        return ToolOutput::err("missing required argument `backup_id` (see database_backups)");
    };
    let meta = match dbbackup::load(id) {
        Ok(m) => m,
        Err(e) => return ToolOutput::err(e),
    };
    let user = arg_str(args, "user").map(String::from);
    if let Some(u) = &user {
        if !valid_ident(u) {
            return ToolOutput::err("invalid `user`");
        }
    }
    let password = arg_str(args, "password").map(String::from);
    let force = arg_bool(args, "force").unwrap_or(false);
    st.audit.log(
        Kind::Granted,
        client,
        TOOL,
        &format!("backup_id={} target={} force={force}", q(id), q(&meta.target.describe())),
    );
    match dbbackup::restore(st, &meta, user, password, force, client).await {
        Ok(msg) => ToolOutput::ok(msg),
        Err(e) => ToolOutput::err(e),
    }
}
