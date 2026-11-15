//! read_file / write_file / list_directory

use super::{arg_bool, arg_str, arg_u64, denied, ToolOutput};
use crate::audit::{q, Kind};
use crate::config;
use crate::state::AppState;
use serde_json::Value;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

async fn blocking<F>(f: F) -> Result<String, String>
where
    F: FnOnce() -> Result<String, String> + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(|e| format!("internal error: {e}"))?
}

pub async fn read_file(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "read_file";
    let Some(path) = arg_str(args, "path") else {
        return ToolOutput::err("missing required argument `path`");
    };
    let what = format!("path={}", q(path));
    if !path.starts_with('/') {
        return ToolOutput::err("`path` must be absolute");
    }
    if let Err(reason) = st.policy.check_read_path(path) {
        return denied(st, client, TOOL, &what, &reason);
    }
    st.audit.log(Kind::Granted, client, TOOL, &what);
    let limit = st.cfg.limits.max_read_bytes.max(1);
    let max = arg_u64(args, "max_bytes").map(|v| v as usize).unwrap_or(limit).clamp(1, limit);
    let tail = arg_u64(args, "tail_lines").map(|v| v as usize);
    let p = path.to_string();
    match blocking(move || read_file_blocking(&p, max, tail)).await {
        Ok(text) => ToolOutput::ok(text),
        Err(e) => ToolOutput::err(e),
    }
}

fn read_file_blocking(path: &str, max: usize, tail: Option<usize>) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if meta.is_dir() {
        return Err(format!("{path} is a directory — use list_directory"));
    }
    let size = meta.len();
    let mut f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut buf = Vec::new();
    let mut skipped_start = false;
    if tail.is_some() && size > max as u64 {
        f.seek(SeekFrom::Start(size - max as u64)).map_err(|e| e.to_string())?;
        skipped_start = true;
    }
    (&mut f).take(max as u64).read_to_end(&mut buf).map_err(|e| format!("{path}: {e}"))?;
    if buf.iter().take(8192).any(|&b| b == 0) {
        return Ok(format!(
            "{path}: binary file ({size} bytes) — use execute_command with `file`, `xxd` or `strings` to inspect it"
        ));
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    if let Some(n) = tail {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(n);
        return Ok(lines[start..].join("\n"));
    }
    let mut out = text;
    if !skipped_start && buf.len() >= max && (size == 0 || size > max as u64) {
        out.push_str(&format!("\n\n[truncated: showing the first {max} bytes of {size}; use tail_lines or execute_command to see more]"));
    }
    Ok(out)
}

pub async fn write_file(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "write_file";
    let (Some(path), Some(content)) = (arg_str(args, "path"), arg_str(args, "content")) else {
        return ToolOutput::err("missing required arguments `path` and `content`");
    };
    let mode = arg_str(args, "mode").unwrap_or("overwrite");
    if mode != "overwrite" && mode != "append" {
        return ToolOutput::err("`mode` must be `overwrite` or `append`");
    }
    let create_dirs = arg_bool(args, "create_dirs").unwrap_or(false);
    let backup = arg_bool(args, "backup").unwrap_or(true);
    let what = format!("path={} mode={mode} bytes={}", q(path), content.len());
    if let Err(reason) = st.policy.check_write_path(path) {
        return denied(st, client, TOOL, &what, &reason);
    }
    // File content goes through the same raw scan as commands (e.g. a script containing `rm -rf /`).
    if let Err(reason) = st.policy.check_raw_content(content) {
        return denied(st, client, TOOL, &what, &format!("file content: {reason}"));
    }
    st.audit.log(Kind::Granted, client, TOOL, &what);
    let (p, c, append) = (path.to_string(), content.to_string(), mode == "append");
    match blocking(move || write_file_blocking(&p, &c, append, create_dirs, backup)).await {
        Ok(msg) => {
            st.audit.log(Kind::Result, client, TOOL, &format!("ok msg={}", q(&msg)));
            ToolOutput::ok(msg)
        }
        Err(e) => {
            st.audit.log(Kind::Error, client, TOOL, &format!("error={}", q(&e)));
            ToolOutput::err(e)
        }
    }
}

fn write_file_blocking(path: &str, content: &str, append: bool, create_dirs: bool, backup: bool) -> Result<String, String> {
    let p = Path::new(path);
    if p.is_dir() {
        return Err(format!("{path} is a directory"));
    }
    if let Some(parent) = p.parent() {
        if !parent.exists() {
            if create_dirs {
                std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            } else {
                return Err(format!(
                    "parent directory {} does not exist (set create_dirs=true)",
                    parent.display()
                ));
            }
        }
    }
    let mut backup_note = String::new();
    if backup && !append && p.is_file() {
        let dir = Path::new(config::BACKUP_DIR);
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create backup dir: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f");
        let name = path.trim_start_matches('/').replace('/', "__");
        let dest = dir.join(format!("{ts}__{name}"));
        std::fs::copy(p, &dest).map_err(|e| format!("backup failed ({e}); file not modified"))?;
        backup_note = format!(" (previous version backed up to {})", dest.display());
    }
    if append {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(p)
            .map_err(|e| format!("{path}: {e}"))?;
        f.write_all(content.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
    } else {
        std::fs::write(p, content).map_err(|e| format!("{path}: {e}"))?;
    }
    let verb = if append { "appended" } else { "wrote" };
    Ok(format!("{verb} {} bytes to {path}{backup_note}", content.len()))
}

pub async fn list_directory(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "list_directory";
    let Some(path) = arg_str(args, "path") else {
        return ToolOutput::err("missing required argument `path`");
    };
    let what = format!("path={}", q(path));
    if !path.starts_with('/') {
        return ToolOutput::err("`path` must be absolute");
    }
    if let Err(reason) = st.policy.check_read_path(path) {
        return denied(st, client, TOOL, &what, &reason);
    }
    st.audit.log(Kind::Granted, client, TOOL, &what);
    let show_hidden = arg_bool(args, "show_hidden").unwrap_or(true);
    let p = path.to_string();
    match blocking(move || list_dir_blocking(&p, show_hidden)).await {
        Ok(text) => ToolOutput::ok(text),
        Err(e) => ToolOutput::err(e),
    }
}

#[cfg(unix)]
fn mode_string(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode();
    let mut s = String::with_capacity(9);
    for shift in [6u32, 3, 0] {
        let bits = (m >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

#[cfg(not(unix))]
fn mode_string(_meta: &std::fs::Metadata) -> String {
    "---------".into()
}

fn list_dir_blocking(path: &str, show_hidden: bool) -> Result<String, String> {
    const MAX: usize = 2000;
    let rd = std::fs::read_dir(path).map_err(|e| format!("{path}: {e}"))?;
    let mut rows: Vec<(bool, String, String)> = Vec::new();
    let mut total = 0usize;
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        total += 1;
        if rows.len() >= MAX {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else { continue };
        let ft = meta.file_type();
        let kind = if ft.is_dir() {
            'd'
        } else if ft.is_symlink() {
            'l'
        } else {
            '-'
        };
        let modified = meta
            .modified()
            .ok()
            .map(|t| chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "?".into());
        let mut display = name.clone();
        if ft.is_dir() {
            display.push('/');
        }
        if ft.is_symlink() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                display.push_str(&format!(" -> {}", target.display()));
            }
        }
        let line = format!("{kind}{} {:>12} {modified}  {display}", mode_string(&meta), meta.len());
        rows.push((ft.is_dir(), name, line));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut out = format!("{path}  ({total} entries)\n");
    for (_, _, line) in &rows {
        out.push_str(line);
        out.push('\n');
    }
    if total > rows.len() {
        out.push_str(&format!("... {} more entries not shown\n", total - rows.len()));
    }
    Ok(out)
}
