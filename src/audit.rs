//! Append-only audit log: every GRANTED / DENIED / RESULT / AUTH event with an exact timestamp.
//!
//! Line format:
//! `[2026-11-15 14:03:22.123 +08:00] [DENIED ] client=1.2.3.4 tool=execute_command cmd="rm -rf ./" reason="..."`

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

pub struct AuditLog {
    path: String,
    file: Mutex<Option<File>>,
    echo_stderr: bool,
}

#[derive(Clone, Copy)]
pub enum Kind {
    Granted,
    Denied,
    Result,
    AuthFail,
    System,
    Error,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Granted => "GRANTED",
            Kind::Denied => "DENIED ",
            Kind::Result => "RESULT ",
            Kind::AuthFail => "AUTHFAIL",
            Kind::System => "SYSTEM ",
            Kind::Error => "ERROR  ",
        }
    }
}

/// Quote a value for the log (single line, JSON escaped, capped at 64 KiB).
pub fn q(s: &str) -> String {
    const MAX: usize = 64 * 1024;
    if s.len() > MAX {
        let mut cut = MAX;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut v = serde_json::to_string(&s[..cut]).unwrap_or_default();
        v.push_str(&format!("...(+{} bytes)", s.len() - cut));
        v
    } else {
        serde_json::to_string(s).unwrap_or_default()
    }
}

pub fn now_stamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string()
}

fn open_append(path: &str) -> std::io::Result<File> {
    if let Some(dir) = Path::new(path).parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

impl AuditLog {
    pub fn open(path: &str, echo_stderr: bool) -> AuditLog {
        let file = match open_append(path) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("[myssh-mcp] WARNING: cannot open audit log {path}: {e} (logging to stderr only)");
                None
            }
        };
        AuditLog { path: path.to_string(), file: Mutex::new(file), echo_stderr }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Write one audit line. `fields` is already formatted (`key=value key2="quoted"`).
    pub fn log(&self, kind: Kind, client: &str, tool: &str, fields: &str) {
        let mut line = format!("[{}] [{}] client={}", now_stamp(), kind.label(), client);
        if !tool.is_empty() {
            line.push_str(" tool=");
            line.push_str(tool);
        }
        if !fields.is_empty() {
            line.push(' ');
            line.push_str(fields);
        }
        line.push('\n');

        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Re-open if the file was rotated away / deleted / never opened.
        let stale = match guard.as_ref() {
            None => true,
            Some(_) => !Path::new(&self.path).exists(),
        };
        if stale {
            *guard = open_append(&self.path).ok();
        }
        if let Some(f) = guard.as_mut() {
            if f.write_all(line.as_bytes()).is_err() {
                *guard = None;
            } else {
                let _ = f.flush();
            }
        }
        drop(guard);
        if self.echo_stderr {
            eprint!("{line}");
        }
    }

    pub fn system(&self, msg: &str) {
        self.log(Kind::System, "-", "", &format!("msg={}", q(msg)));
    }
}
