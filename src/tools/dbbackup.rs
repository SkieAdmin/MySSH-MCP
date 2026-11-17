//! Database backups: create (mysqldump / pg_dump / sqlite .backup), list, load, restore.
//!
//! Files live in /var/backups/myssh-mcp/db (root only, tamper-protected from the AI):
//!   <id>.sql.gz | <id>.dump | <id>.sqlite   the backup
//!   <id>.meta.json                           what / when / why / how to reconnect (no password)

use super::db::{missing_binary, DbTarget, Tool};
use crate::audit::{q, Kind};
use crate::config;
use crate::exec::{self, ExecSpec};
use crate::policy::shell_quote;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMeta {
    pub id: String,
    pub created: String,
    pub target: DbTarget,
    /// Database that was dumped (None = all MySQL databases).
    pub database: Option<String>,
    pub file: String,
    pub size_bytes: u64,
    pub reason: String,
    pub client: String,
}

pub fn human_size(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn join_quoted(argv: &[String]) -> String {
    argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

fn slug(s: &str) -> String {
    let base = Path::new(s).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let base = if base.is_empty() { s.to_string() } else { base };
    let out: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .take(40)
        .collect();
    if out.is_empty() {
        "db".into()
    } else {
        out
    }
}

fn private_dir(dir: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {dir}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [config::BACKUP_DIR, dir] {
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

fn chmod600(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(unix)]
fn free_mb(path: &str) -> Option<u64> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: statvfs only writes into the zero-initialised struct passed to it.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some((s.f_bavail as u64).saturating_mul(s.f_frsize as u64) / (1024 * 1024))
}

#[cfg(not(unix))]
fn free_mb(_path: &str) -> Option<u64> {
    None
}

async fn run_script(script: String, env: Vec<(String, String)>, timeout_secs: u64) -> Result<exec::ExecOutput, String> {
    exec::run(ExecSpec {
        program: "/bin/bash".into(),
        args: vec!["-c".into(), script],
        cwd: Some("/tmp".into()),
        env,
        stdin: None,
        timeout: Duration::from_secs(timeout_secs.max(10)),
        max_output: 64 * 1024,
    })
    .await
}

fn failure_text(o: &exec::ExecOutput) -> String {
    let detail = format!("{} {}", o.stderr.trim(), o.stdout.trim()).trim().to_string();
    if detail.is_empty() {
        o.status_line()
    } else {
        format!("{} — {detail}", o.status_line())
    }
}

/// Take a backup (serialized with other backups / restores).
pub async fn create(
    st: &AppState,
    t: &DbTarget,
    db: Option<String>,
    reason: &str,
    client: &str,
) -> Result<BackupMeta, String> {
    let _guard = st.db_lock.lock().await;
    create_inner(st, t, db, reason, client).await
}

async fn create_inner(
    st: &AppState,
    t: &DbTarget,
    db: Option<String>,
    reason: &str,
    client: &str,
) -> Result<BackupMeta, String> {
    let result = dump(st, t, &db, reason, client).await;
    match &result {
        Ok(m) => st.audit.log(
            Kind::Backup,
            client,
            "database_backup",
            &format!(
                "status=OK id={} target={} size_bytes={} reason={}",
                m.id,
                q(&t.describe()),
                m.size_bytes,
                q(reason)
            ),
        ),
        Err(e) => st.audit.log(
            Kind::Backup,
            client,
            "database_backup",
            &format!("status=FAILED target={} reason={} error={}", q(&t.describe()), q(reason), q(e)),
        ),
    }
    cleanup_old(st.cfg.database.keep_days);
    result
}

async fn dump(st: &AppState, t: &DbTarget, db: &Option<String>, reason: &str, client: &str) -> Result<BackupMeta, String> {
    let dir = config::DB_BACKUP_DIR;
    private_dir(dir)?;
    if let Some(free) = free_mb(dir) {
        let min = st.cfg.database.min_free_mb;
        if free < min {
            return Err(format!("only {free} MB free on the backup disk (min_free_mb = {min})"));
        }
    }
    let now = chrono::Local::now();
    let label = match t.engine.as_str() {
        "sqlite" => t.path.clone().unwrap_or_default(),
        _ => db.clone().unwrap_or_else(|| "all".into()),
    };
    let id = format!("{}-{}-{}", now.format("%Y%m%d-%H%M%S-%3f"), t.engine, slug(&label));
    let ext = match t.engine.as_str() {
        "mysql" => "sql.gz",
        "postgres" => "dump",
        _ => "sqlite",
    };
    let file = format!("{dir}/{id}.{ext}");

    let mut env = Vec::new();
    let (script, argv) = match t.engine.as_str() {
        "mysql" => {
            let mut extra: Vec<String> = ["--single-transaction", "--quick", "--routines", "--triggers", "--default-character-set=utf8mb4"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            match db {
                Some(d) => {
                    extra.push("--databases".into());
                    extra.push(d.clone());
                }
                None => extra.push("--all-databases".into()),
            }
            let argv = t.argv(Tool::Dump, &extra, &mut env);
            (format!("set -o pipefail; {} | gzip -c > {}", join_quoted(&argv), shell_quote(&file)), argv)
        }
        "postgres" => {
            let d = db.clone().unwrap_or_else(|| "postgres".into());
            let argv = t.argv(Tool::Dump, &["--format=custom".into(), format!("--dbname={d}")], &mut env);
            (format!("{} > {}", join_quoted(&argv), shell_quote(&file)), argv)
        }
        _ => {
            let src = t.path.clone().unwrap_or_default();
            if !Path::new(&src).is_file() {
                return Err(format!("sqlite database {src} does not exist"));
            }
            let argv = t.argv(Tool::Client, &[src, format!(".backup '{file}'")], &mut env);
            (join_quoted(&argv), argv)
        }
    };
    if let Some(bin) = missing_binary(&argv) {
        return Err(format!("`{bin}` is not installed on this server"));
    }

    let out = run_script(script, env, st.cfg.database.backup_timeout_secs).await;
    let failure = match &out {
        Ok(o) if o.success() => None,
        Ok(o) => Some(failure_text(o)),
        Err(e) => Some(e.clone()),
    };
    let size = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
    if let Some(err) = failure.or_else(|| if size == 0 { Some("backup file is empty".into()) } else { None }) {
        let _ = std::fs::remove_file(&file);
        return Err(err);
    }
    chmod600(&file);

    let meta = BackupMeta {
        id: id.clone(),
        created: crate::audit::now_stamp(),
        target: t.clone(),
        database: if t.engine == "sqlite" { t.path.clone() } else { db.clone() },
        file,
        size_bytes: size,
        reason: reason.to_string(),
        client: client.to_string(),
    };
    let meta_path = format!("{dir}/{id}.meta.json");
    let json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    std::fs::write(&meta_path, json).map_err(|e| format!("cannot write {meta_path}: {e}"))?;
    chmod600(&meta_path);
    Ok(meta)
}

/// Delete backups older than `keep_days` (0 = keep forever).
fn cleanup_old(keep_days: u64) {
    if keep_days == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(config::DB_BACKUP_DIR) else { return };
    let max_age = Duration::from_secs(keep_days.saturating_mul(86_400));
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let ours = [".meta.json", ".sql.gz", ".dump", ".sqlite"].iter().any(|s| name.ends_with(s));
        if !ours {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|age| age > max_age)
            .unwrap_or(false);
        if old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// All backups, newest first.
pub fn list() -> Vec<BackupMeta> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(config::DB_BACKUP_DIR) else { return out };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".meta.json") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            if let Ok(m) = serde_json::from_str::<BackupMeta>(&text) {
                out.push(m);
            }
        }
    }
    out.sort_by(|a, b| b.id.cmp(&a.id));
    out
}

pub fn load(id: &str) -> Result<BackupMeta, String> {
    let valid = !id.is_empty()
        && !id.contains("..")
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !valid {
        return Err("invalid backup_id".into());
    }
    let path = format!("{}/{id}.meta.json", config::DB_BACKUP_DIR);
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("backup `{id}` not found — list them with database_backups"))?;
    let meta: BackupMeta = serde_json::from_str(&text).map_err(|e| format!("corrupt backup metadata: {e}"))?;
    if !Path::new(&meta.file).is_file() {
        return Err(format!("backup file {} is missing", meta.file));
    }
    Ok(meta)
}

/// Restore a backup. A safety backup of the current state is taken first, so the restore itself
/// can be undone.
pub async fn restore(
    st: &AppState,
    meta: &BackupMeta,
    user: Option<String>,
    password: Option<String>,
    force: bool,
    client: &str,
) -> Result<String, String> {
    let _guard = st.db_lock.lock().await;
    let mut t = meta.target.clone();
    t.password = password;
    if user.is_some() {
        t.user = user;
    }

    let mut notes = Vec::new();
    match create_inner(st, &t, meta.database.clone(), &format!("safety backup before restoring {}", meta.id), client).await {
        Ok(safety) => notes.push(format!(
            "🛟 Safety backup of the state before this restore: `{}` — restore it to undo this restore.",
            safety.id
        )),
        Err(e) if force => notes.push(format!("⚠ No safety backup of the previous state ({e}); continuing because force=true.")),
        Err(e) => {
            return Err(format!(
                "could not back up the current state before restoring ({e}). If the database is gone or broken and you still want to restore, call database_restore again with force=true."
            ))
        }
    }

    let file = meta.file.as_str();
    let mut env = Vec::new();
    let (script, argv) = match t.engine.as_str() {
        "mysql" => {
            // The dump contains CREATE DATABASE + USE, so connect without a default database.
            let argv = t.argv(Tool::Client, &[], &mut env);
            let script = match &meta.database {
                Some(db) => format!(
                    "set -o pipefail; {{ printf '%s\\n' {}; gunzip -c {}; }} | {}",
                    shell_quote(&format!("DROP DATABASE IF EXISTS `{db}`;")),
                    shell_quote(file),
                    join_quoted(&argv)
                ),
                None => format!("set -o pipefail; gunzip -c {} | {}", shell_quote(file), join_quoted(&argv)),
            };
            (script, argv)
        }
        "postgres" => {
            let d = meta.database.clone().unwrap_or_else(|| "postgres".into());
            // Recreate the database if it was dropped (error ignored when it still exists).
            let create = t.argv(Tool::CreateDb, &[d.clone()], &mut env);
            let argv = t.argv(
                Tool::Restore,
                &["--clean".into(), "--if-exists".into(), "--single-transaction".into(), format!("--dbname={d}")],
                &mut env,
            );
            let script = format!(
                "{} >/dev/null 2>&1 || true; {} < {}",
                join_quoted(&create),
                join_quoted(&argv),
                shell_quote(file)
            );
            (script, argv)
        }
        _ => {
            let path = t.path.clone().unwrap_or_default();
            let argv = t.argv(Tool::Client, &[path, format!(".restore '{file}'")], &mut env);
            (join_quoted(&argv), argv)
        }
    };
    if let Some(bin) = missing_binary(&argv) {
        return Err(format!("`{bin}` is not installed on this server"));
    }

    let out = run_script(script, env, st.cfg.database.backup_timeout_secs).await?;
    // The database changed: never reuse an older automatic backup after a restore.
    if let Ok(mut m) = st.db_last_backup.lock() {
        m.clear();
    }
    if !out.success() {
        let err = failure_text(&out);
        st.audit.log(
            Kind::Restore,
            client,
            "database_restore",
            &format!("status=FAILED id={} target={} error={}", meta.id, q(&t.describe()), q(&err)),
        );
        return Err(format!("restore of `{}` failed: {err}\n{}", meta.id, notes.join("\n")));
    }
    st.audit.log(
        Kind::Restore,
        client,
        "database_restore",
        &format!("status=OK id={} target={}", meta.id, q(&t.describe())),
    );
    notes.insert(
        0,
        format!("✅ Restored backup `{}` ({}) into {}.", meta.id, meta.created, t.describe()),
    );
    let tail = out.render();
    Ok(format!("{}\n\n{tail}", notes.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_slugs() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(slug("shop"), "shop");
        assert_eq!(slug("/var/lib/app/data.db"), "data_db");
        assert_eq!(slug("we!rd name"), "we_rd_name");
    }

    #[test]
    fn rejects_path_traversal_ids() {
        assert!(load("../../etc/passwd").is_err());
        assert!(load("a/b").is_err());
        assert!(load("").is_err());
    }
}
