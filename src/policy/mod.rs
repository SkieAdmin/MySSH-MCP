//! The safety policy. Every command / file write / SQL query sent by the AI goes through here
//! before anything is executed.
//!
//! Layers:
//! 1. raw text scan  - catastrophic patterns anywhere in the text (also inside python -c "...")
//! 2. shell parsing  - every simple command, pipeline, `$(...)`, `bash -c`, `sudo`, `xargs`, ...
//!    is unwrapped and checked by per-program rules (rm, mv, chmod, dd, systemctl, docker, ...)
//! 3. self-protection - the AI can never touch MySSH-MCP's own config, log, binary, service or key.
//!
//! This is a guard-rail against mistakes and prompt-injected AIs, not a sandbox: a determined
//! human with root can always find a way around a deny-list.

pub mod paths;
mod rules_fs;
mod rules_sys;
pub mod shell;
mod sql;
#[cfg(test)]
mod tests;

use crate::config::{self, PolicyConfig};
use paths::*;
use regex::Regex;
use std::sync::LazyLock;

pub type Verdict = Result<(), String>;

pub const SELF_MSG: &str =
    "MySSH-MCP's own files (config, audit log, binary, service, API key, backups) are tamper-protected";
pub(crate) const PIPE_FETCH_MSG: &str = "piping downloaded content straight into an interpreter (curl | bash) is blocked — download the script to a file, review it, then run it (or set allow_remote_script_pipe = true)";
pub(crate) const PIPE_DECODE_MSG: &str =
    "piping decoded/obfuscated data into an interpreter is blocked — it hides the real command from inspection";

pub(crate) const DECODERS: &[&str] = &[
    "base64", "base32", "basenc", "xxd", "uudecode", "rev", "openssl", "gunzip", "gzip", "zcat",
    "bzcat", "bunzip2", "bzip2", "xzcat", "unxz", "xz", "zstdcat", "zstd",
];
pub(crate) const FETCHERS: &[&str] =
    &["curl", "wget", "fetch", "nc", "ncat", "netcat", "socat", "aria2c", "http", "https"];

pub(crate) static FETCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:curl|wget|fetch|nc|ncat|netcat|socat|aria2c)\b").unwrap()
});
pub(crate) static DECODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:base64|base32|basenc|xxd|uudecode|openssl|gunzip|zcat|bzcat|xzcat|zstdcat)\b").unwrap()
});

static RAW_RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let rules: &[(&str, &'static str)] = &[
        (r"--no-preserve-root", "`--no-preserve-root` is never allowed"),
        (
            r#"(?:^|[\s;&|('"`])rm\s+(?:-{1,2}[A-Za-z-]+\s+)*-{1,2}[A-Za-z-]*[rR][A-Za-z-]*\s+(?:-{1,2}[A-Za-z-]+\s+)*['"]?(?:/|/\*|/\.\*|\.|\./|\./\*|\.\*|\.\.|\.\./|\.\./\*|\*|~|~/|~/\*)['"]?(?:[\s;&|)'"`]|$)"#,
            "recursive delete of /, ., .., * or ~ is blocked",
        ),
        (
            r#"(?:^|[\s;&|('"`])mkfs(?:\.[A-Za-z0-9]+)?\s"#,
            "formatting filesystems (mkfs) is blocked",
        ),
        (
            r"\bdd\b[^;&|\n]*\bof=/dev/(?:sd|hd|vd|xvd|nvme|mmcblk|dm-|md|mapper|disk|loop|root|nbd)",
            "writing raw data to a disk device with dd is blocked",
        ),
        (
            r">\s*/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|dm-\d|md\d|disk/|mapper/|nbd\d)",
            "redirecting output onto a disk device is blocked",
        ),
        (
            r"(?:>\s*|\btee\s+(?:-\S+\s+)*)/proc/sysrq-trigger",
            "writing to /proc/sysrq-trigger (instant reboot/crash) is blocked",
        ),
        (
            r#"(?:^|[\s;&|('"`])ch(?:mod|own|grp)\s+(?:[^\s;&|]+\s+)*-[A-Za-z]*R[A-Za-z]*\s+(?:[^\s;&|]+\s+)*['"]?/['"]?(?:[\s;&|)'"`]|$)"#,
            "recursive chmod/chown of / is blocked",
        ),
        (
            r"\b(?:shred|wipefs|blkdiscard)\b[^;&|\n]*\s/dev/",
            "wiping block devices is blocked",
        ),
    ];
    rules.iter().map(|(re, why)| (Regex::new(re).expect("valid builtin regex"), *why)).collect()
});

static NOSQL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bflushall\b|\bflushdb\b|\.dropDatabase\s*\(").unwrap());
static FN_DEF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:function([A-Za-z_][A-Za-z0-9_]*)(?:\(\))?\{|([A-Za-z_][A-Za-z0-9_]*|:)\(\)\{)").unwrap()
});

const KEYWORDS: &[&str] = &[
    "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "case", "esac", "{",
    "}", "!", "[[", "]]", "function",
];

pub struct Policy {
    pub(crate) allow_reboot: bool,
    pub(crate) allow_remote_script_pipe: bool,
    pub(crate) allow_destructive_sql: bool,
    pub(crate) allow_privileged_containers: bool,
    pub(crate) protected_dirs: Vec<String>,
    pub(crate) protected_files: Vec<String>,
    pub(crate) protected_services: Vec<String>,
    pub(crate) protected_procs: Vec<String>,
    pub(crate) critical_packages: Vec<String>,
    pub(crate) extra: Vec<Regex>,
    pub(crate) self_paths: Vec<String>,
    pub(crate) mcp_port: u16,
    pub(crate) own_pid: String,
    pub(crate) kernel: String,
}

/// A simple command after stripping wrappers like `sudo`, `env`, `nohup`, `timeout`, `xargs`.
pub(crate) struct Invocation {
    pub argv: Vec<String>,
    pub via_xargs: bool,
    /// Command strings that will be run by a wrapper (`su -c`, `watch`, `flock -c`, `env -S`).
    pub inner: Vec<String>,
}

/// Per-command context handed to the program rules.
pub(crate) struct Ctx<'a> {
    /// Basename of the program (`rm`), and the word as written (`/usr/bin/rm`, `./deploy.sh`).
    pub prog: &'a str,
    pub exe: &'a str,
    pub args: &'a [String],
    pub cwd: Option<&'a str>,
    pub via_xargs: bool,
    pub depth: u8,
}

impl Policy {
    pub fn new(cfg: &PolicyConfig, log_file: &str, mcp_port: u16) -> Result<Policy, String> {
        let mut extra = Vec::new();
        for p in &cfg.extra_deny_patterns {
            extra.push(
                Regex::new(p).map_err(|e| format!("invalid extra_deny_patterns entry `{p}`: {e}"))?,
            );
        }
        let protected_dirs: Vec<String> =
            cfg.protected_dirs.iter().filter_map(|d| normalize(d, Some("/"))).collect();
        let protected_files = cfg
            .protected_files
            .iter()
            .map(|f| {
                if !f.contains('/') {
                    return f.clone();
                }
                let n = normalize(f, Some("/")).unwrap_or_else(|| f.clone());
                if f.ends_with('/') && n != "/" {
                    format!("{n}/")
                } else {
                    n
                }
            })
            .collect();

        let mut self_paths: Vec<String> = [
            config::CONFIG_DIR,
            config::BINARY_PATH,
            config::UNIT_PATH,
            config::LOGROTATE_PATH,
            config::API_KEY_FILE,
            config::BACKUP_DIR,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if let Some(log) = normalize(log_file, Some("/")) {
            if let Some(parent) = std::path::Path::new(&log).parent() {
                let parent = parent.to_string_lossy().to_string();
                let shared = parent == "/"
                    || CORE_SYSTEM_DIRS.contains(&parent.as_str())
                    || protected_dirs.contains(&parent);
                if !shared {
                    self_paths.push(parent);
                }
            }
            self_paths.push(log);
        }
        if let Ok(exe) = std::env::current_exe() {
            let s = exe.to_string_lossy().to_string();
            if s.starts_with('/') && !s.contains("/target/") {
                self_paths.push(s.trim_end_matches(" (deleted)").to_string());
            }
        }
        self_paths.sort();
        self_paths.dedup();

        let mut protected_procs: Vec<String> = cfg
            .protected_services
            .iter()
            .map(|s| s.trim_end_matches(".service").trim_end_matches(".socket").to_lowercase())
            .collect();
        for p in ["sshd", "systemd", "init", config::SERVICE_NAME] {
            protected_procs.push(p.to_string());
        }
        protected_procs.sort();
        protected_procs.dedup();

        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        Ok(Policy {
            allow_reboot: cfg.allow_reboot,
            allow_remote_script_pipe: cfg.allow_remote_script_pipe,
            allow_destructive_sql: cfg.allow_destructive_sql,
            allow_privileged_containers: cfg.allow_privileged_containers,
            protected_dirs,
            protected_files,
            protected_services: cfg.protected_services.clone(),
            protected_procs,
            critical_packages: cfg.critical_packages.clone(),
            extra,
            self_paths,
            mcp_port,
            own_pid: std::process::id().to_string(),
            kernel,
        })
    }

    // ------------------------------------------------------------------ public API

    /// Check a shell command line that would be run with `bash -c` in `cwd`.
    pub fn check_command(&self, cmd: &str, cwd: &str) -> Verdict {
        if cmd.trim().is_empty() {
            return Err("empty command".into());
        }
        self.check_raw(cmd)?;
        self.check_shell(cmd, normalize(cwd, Some("/")), 0)
    }

    /// Check a path that the `write_file` tool (or sqlite) would create / overwrite.
    pub fn check_write_path(&self, path: &str) -> Verdict {
        if !path.starts_with('/') {
            return Err("path must be absolute".into());
        }
        if path.contains(config::API_KEY_FILE_MARKER) {
            return Err(SELF_MSG.into());
        }
        let n = normalize(path, Some("/")).ok_or("path cannot contain variables")?;
        self.check_overwrite_target(&n, "write")?;
        const SYSTEM: &[&str] =
            &["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/usr/lib", "/proc", "/sys", "/dev"];
        let mut candidates = vec![n.clone()];
        candidates.extend(real_or_parent(&n));
        for c in &candidates {
            if let Some(d) = SYSTEM.iter().find(|d| is_within(c, d)) {
                return Err(format!(
                    "writing into `{d}` (system binaries/libraries/kernel interfaces) is blocked — install software with apt instead"
                ));
            }
        }
        Ok(())
    }

    /// Raw-text scan of content that will end up on disk (scripts, cron files, systemd units).
    pub fn check_raw_content(&self, text: &str) -> Verdict {
        self.check_raw(text)
    }

    /// Check a path that the `read_file` / `list_directory` tools would read.
    pub fn check_read_path(&self, path: &str) -> Verdict {
        let real = normalize(path, Some("/")).and_then(|n| real_path(&n)).unwrap_or_default();
        if path.contains(config::API_KEY_FILE_MARKER) || real.contains(config::API_KEY_FILE_MARKER) {
            return Err("reading the MySSH-MCP API key file is blocked".into());
        }
        Ok(())
    }

    // ------------------------------------------------------------------ layer 1: raw text

    pub(crate) fn check_raw(&self, text: &str) -> Verdict {
        if text.contains(config::API_KEY_FILE_MARKER) {
            return Err("access to the MySSH-MCP API key file is blocked".into());
        }
        for (re, why) in RAW_RULES.iter() {
            if re.is_match(text) {
                return Err((*why).to_string());
            }
        }
        if is_fork_bomb(text) {
            return Err("fork bomb detected".into());
        }
        if !self.allow_destructive_sql && NOSQL_RE.is_match(text) {
            return Err("FLUSHALL / FLUSHDB / dropDatabase() destroys data — blocked (allow_destructive_sql = false)".into());
        }
        for re in &self.extra {
            if re.is_match(text) {
                return Err(format!("matches the custom deny pattern `{}`", re.as_str()));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ layer 2: shell structure

    pub(crate) fn check_shell(&self, cmd: &str, cwd: Option<String>, depth: u8) -> Verdict {
        if depth > 8 {
            return Err("command nesting is too deep to inspect safely".into());
        }
        let parsed = shell::parse(cmd);
        for sub in &parsed.substitutions {
            self.check_shell(sub, cwd.clone(), depth + 1)?;
        }
        let mut cwd = cwd;
        let mut stdin_consumer = false;
        for c in &parsed.cmds {
            for r in &c.redirects {
                self.check_redirect(r, cwd.as_deref())?;
            }
            let inv = unwrap_wrappers(&c.words);
            for inner in &inv.inner {
                self.check_raw(inner)?;
                self.check_shell(inner, cwd.clone(), depth + 1)?;
            }
            let Some(first) = inv.argv.first() else { continue };
            if first.contains("$(")
                || first.contains('`')
                || (first.starts_with('$') && !first.starts_with("$HOME/") && !first.starts_with("${HOME}/"))
            {
                return Err(format!(
                    "dynamic program name `{first}` cannot be inspected — call the program by its literal name"
                ));
            }
            let prog = basename(first).to_string();
            let args = &inv.argv[1..];
            let ctx = Ctx { prog: &prog, exe: first, args, cwd: cwd.as_deref(), via_xargs: inv.via_xargs, depth };
            self.check_program(&ctx)?;
            if rules_fs::reads_stdin_as_code(&prog, args) {
                stdin_consumer = true;
                self.check_pipe_source(c, &parsed.cmds)?;
            }
            if prog == "cd" || prog == "pushd" {
                let target = args
                    .iter()
                    .map(|s| s.as_str())
                    .find(|a| !a.starts_with('-') || *a == "-")
                    .unwrap_or("~");
                cwd = if target == "-" { None } else { normalize(target, cwd.as_deref()) };
            }
        }
        if stdin_consumer {
            for body in &parsed.heredoc_bodies {
                self.check_raw(body)?;
                self.check_shell(body, cwd.clone(), depth + 1)?;
            }
        }
        Ok(())
    }

    fn check_pipe_source(&self, c: &shell::SimpleCmd, all: &[shell::SimpleCmd]) -> Verdict {
        for prev in all.iter().filter(|p| p.pipeline == c.pipeline && p.pipe_pos < c.pipe_pos) {
            let inv = unwrap_wrappers(&prev.words);
            if let Some(w) = inv.argv.first() {
                let b = basename(w);
                if DECODERS.contains(&b) {
                    return Err(PIPE_DECODE_MSG.into());
                }
                if FETCHERS.contains(&b) && !self.allow_remote_script_pipe {
                    return Err(PIPE_FETCH_MSG.into());
                }
            }
        }
        for r in &c.redirects {
            if r.op == "<" || r.op == "<<<" {
                if DECODE_RE.is_match(&r.target) {
                    return Err(PIPE_DECODE_MSG.into());
                }
                if FETCH_RE.is_match(&r.target) && !self.allow_remote_script_pipe {
                    return Err(PIPE_FETCH_MSG.into());
                }
            }
        }
        Ok(())
    }

    fn check_redirect(&self, r: &shell::Redirect, cwd: Option<&str>) -> Verdict {
        let write = matches!(r.op.as_str(), ">" | ">>" | ">|" | "&>" | "&>>" | "<>");
        if !write {
            return Ok(());
        }
        if self.self_paths.iter().any(|s| r.target.contains(s.as_str())) {
            return Err(format!("redirect into `{}`: {SELF_MSG}", r.target));
        }
        for t in expand_braces(&r.target) {
            if let Some(n) = normalize(&t, cwd) {
                self.check_overwrite_target(&n, "redirect (>)")?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ shared path checks

    /// `p` is one of our own files/dirs or inside one.
    pub(crate) fn self_touch(&self, p: &str) -> bool {
        self.self_paths.iter().any(|s| is_within(p, s))
    }

    /// Deleting/moving/chmod -R'ing `p` would affect our own files.
    pub(crate) fn self_destroy(&self, p: &str) -> bool {
        self.self_touch(p) || self.self_paths.iter().any(|s| is_ancestor(p, s))
    }

    pub(crate) fn self_glob_hit(&self, pattern: &str) -> bool {
        has_glob(pattern) && self.self_paths.iter().any(|s| glob_match(pattern, s))
    }

    /// `p` is a protected directory or a parent of one.
    pub(crate) fn protected_dir_hit(&self, p: &str) -> Option<String> {
        self.protected_dirs.iter().find(|d| p == d.as_str() || is_ancestor(p, d)).cloned()
    }

    pub(crate) fn protected_file_hit(&self, n: &str, globbed: bool) -> Option<String> {
        for f in &self.protected_files {
            let hit = if !f.contains('/') {
                let b = basename(n);
                if globbed { glob_match(b, f) } else { b == f }
            } else if f.ends_with('/') {
                let dir = f.trim_end_matches('/');
                if globbed {
                    let (prefix, _) = glob_prefix(n);
                    is_within(&prefix, dir)
                } else {
                    n.starts_with(f.as_str())
                }
            } else if globbed {
                glob_match(n, f)
            } else {
                n == f
            };
            if hit {
                return Some(f.clone());
            }
        }
        None
    }

    /// Writing / overwriting / truncating the normalized path `n`.
    pub(crate) fn check_overwrite_target(&self, n: &str, verb: &str) -> Verdict {
        let (prefix, glob) = glob_prefix(n);
        if self.self_touch(&prefix) || self.self_glob_hit(n) {
            return Err(format!("{verb} `{n}`: {SELF_MSG}"));
        }
        if is_device(n) {
            return Err(format!("{verb} to raw device `{n}` is blocked (could destroy disks/partitions)"));
        }
        if n == "/proc/sysrq-trigger"
            || n == "/proc/sys/kernel/panic"
            || n.starts_with("/sys/power/")
            || n.ends_with("/device/delete")
        {
            return Err(format!("{verb} to `{n}` could crash or power off the server"));
        }
        if let Some(f) = self.protected_file_hit(n, glob.is_some()) {
            return Err(format!("{verb} on protected file `{f}` is blocked (lock-out / boot protection)"));
        }
        if let Some(real) = real_or_parent(n) {
            self.check_overwrite_target(&real, verb).map_err(|e| format!("{e} (via symlink `{n}`)"))?;
        }
        Ok(())
    }

    /// Deleting `raw` (rm, rmdir, unlink, shred).
    pub(crate) fn check_destroy(&self, raw: &str, cwd: Option<&str>, recursive: bool, verb: &str) -> Verdict {
        for t in expand_braces(raw.trim()) {
            let t = t.as_str();
            if t.is_empty() {
                continue;
            }
            if recursive && ALWAYS_BAD_TARGETS.contains(&t) {
                return Err(format!("`{verb} {t}` would wipe a whole directory tree"));
            }
            if has_dynamic(t) {
                if recursive {
                    return Err(format!(
                        "`{verb} {t}`: the target contains a variable or substitution that could expand to `/` — use a literal path"
                    ));
                }
                continue;
            }
            let Some(n) = normalize(t, cwd) else {
                if recursive {
                    return Err(format!(
                        "`{verb} {t}` on a relative path while the working directory is unknown — use an absolute path"
                    ));
                }
                continue;
            };
            let (prefix, glob) = glob_prefix(&n);
            if self.self_destroy(&prefix) || self.self_glob_hit(&n) {
                return Err(format!("`{verb} {t}`: {SELF_MSG}"));
            }
            let wipes_dir = recursive || glob.as_deref().map(is_bare_wildcard).unwrap_or(false);
            if wipes_dir {
                if depth(&prefix) <= 1 {
                    return Err(format!("`{verb} {t}` would wipe the top-level directory `{prefix}`"));
                }
                if let Some(d) = self.protected_dir_hit(&prefix) {
                    return Err(format!("`{verb} {t}` would destroy protected directory `{d}`"));
                }
            }
            if glob.is_none() {
                if let Some(d) = self.protected_dirs.iter().find(|d| **d == n) {
                    return Err(format!("`{verb}` on protected directory `{d}` is blocked"));
                }
            }
            if let Some(f) = self.protected_file_hit(&n, glob.is_some()) {
                return Err(format!("`{verb}` on protected file `{f}` is blocked"));
            }
            if let Some(real) = real_path(&n) {
                self.check_destroy(&real, None, recursive, verb)
                    .map_err(|e| format!("{e} (via symlink `{t}`)"))?;
            }
        }
        Ok(())
    }
}

/// Canonical path of an existing, non-glob path when it differs from `n` (symlinks).
fn real_path(n: &str) -> Option<String> {
    if has_glob(n) {
        return None;
    }
    std::fs::canonicalize(n)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|r| r.starts_with('/') && r != n)
}

/// Like `real_path`, but for a file that may not exist yet: resolve its parent directory.
fn real_or_parent(n: &str) -> Option<String> {
    if has_glob(n) {
        return None;
    }
    if let Some(r) = real_path(n) {
        return Some(r);
    }
    if std::path::Path::new(n).exists() {
        return None;
    }
    let p = std::path::Path::new(n);
    let parent = std::fs::canonicalize(p.parent()?).ok()?;
    let joined = parent.join(p.file_name()?).to_string_lossy().to_string();
    if joined != n && joined.starts_with('/') {
        Some(joined)
    } else {
        None
    }
}

fn is_device(n: &str) -> bool {
    if !n.starts_with("/dev/") {
        return false;
    }
    const OK: &[&str] = &[
        "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/stdout",
        "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/console",
    ];
    !(OK.contains(&n)
        || n.starts_with("/dev/fd/")
        || n.starts_with("/dev/shm/")
        || n.starts_with("/dev/pts/")
        || n.starts_with("/dev/mqueue/"))
}

fn is_fork_bomb(text: &str) -> bool {
    let s: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if s.contains(":(){:|:&};:") {
        return true;
    }
    for cap in FN_DEF_RE.captures_iter(&s) {
        let name = cap.get(1).or_else(|| cap.get(2)).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if s.contains(&format!("{name}|{name}&")) || s.contains(&format!("{name}&{name}&")) {
            return true;
        }
    }
    false
}

fn is_assignment(w: &str) -> bool {
    match w.find('=') {
        Some(pos) if pos > 0 => {
            let name = w[..pos].trim_end_matches('+');
            !name.is_empty()
                && name
                    .chars()
                    .enumerate()
                    .all(|(k, c)| c == '_' || c.is_ascii_alphabetic() || (k > 0 && c.is_ascii_digit()))
        }
        _ => false,
    }
}

/// Skip options of a wrapper command; returns the index of the first non-option word.
fn skip_opts(words: &[String], mut i: usize, value_opts: &[&str]) -> usize {
    while i < words.len() {
        let w = words[i].as_str();
        if w == "--" {
            return i + 1;
        }
        if !w.starts_with('-') || w == "-" {
            break;
        }
        i += if value_opts.contains(&w) { 2 } else { 1 };
    }
    i
}

pub(crate) fn unwrap_wrappers(words: &[String]) -> Invocation {
    let mut i = 0;
    let mut via_xargs = false;
    let mut inner = Vec::new();
    loop {
        while i < words.len() && (is_assignment(&words[i]) || KEYWORDS.contains(&words[i].as_str())) {
            i += 1;
        }
        if i >= words.len() {
            break;
        }
        let p = basename(&words[i]).to_string();
        match p.as_str() {
            "sudo" | "doas" => {
                i = skip_opts(
                    words,
                    i + 1,
                    &[
                        "-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-R", "-T", "--user",
                        "--group", "--prompt", "--chdir", "--close-from", "--host", "--role",
                        "--type", "--other-user", "--command-timeout",
                    ],
                )
            }
            "env" => {
                i += 1;
                while i < words.len() {
                    let w = words[i].as_str();
                    if w == "--" {
                        i += 1;
                        break;
                    }
                    if is_assignment(w) {
                        i += 1;
                        continue;
                    }
                    if w == "-S" || w == "--split-string" {
                        if let Some(s) = words.get(i + 1) {
                            inner.push(s.clone());
                        }
                        i += 2;
                        continue;
                    }
                    if let Some(s) = w.strip_prefix("--split-string=") {
                        inner.push(s.to_string());
                        i += 1;
                        continue;
                    }
                    if w == "-u" || w == "-C" || w == "--unset" || w == "--chdir" {
                        i += 2;
                        continue;
                    }
                    if w.starts_with('-') && w.len() > 1 {
                        i += 1;
                        continue;
                    }
                    break;
                }
            }
            "nohup" | "builtin" | "unbuffer" | "busybox" => i += 1,
            "command" | "exec" | "time" | "setsid" => {
                let lookup = p == "command"
                    && words.get(i + 1).map(|w| w == "-v" || w == "-V").unwrap_or(false);
                if lookup {
                    return Invocation { argv: Vec::new(), via_xargs, inner };
                }
                i = skip_opts(words, i + 1, &["-a"]);
            }
            "nice" => i = skip_opts(words, i + 1, &["-n", "--adjustment"]),
            "ionice" => {
                i = skip_opts(words, i + 1, &["-c", "-n", "-p", "-P", "-u", "--class", "--classdata"])
            }
            "stdbuf" => {
                i = skip_opts(words, i + 1, &["-i", "-o", "-e", "--input", "--output", "--error"])
            }
            "timeout" => {
                i = skip_opts(words, i + 1, &["-s", "-k", "--signal", "--kill-after"]) + 1;
            }
            "taskset" | "chrt" => i = skip_opts(words, i + 1, &[]) + 1,
            "chroot" => i = skip_opts(words, i + 1, &["--userspec", "--groups"]) + 1,
            "flock" => {
                i = skip_opts(words, i + 1, &["-w", "--timeout", "-E", "--conflict-exit-code"]) + 1;
                if let Some(w) = words.get(i) {
                    if w == "-c" || w == "--command" {
                        if let Some(s) = words.get(i + 1) {
                            inner.push(s.clone());
                        }
                        return Invocation { argv: Vec::new(), via_xargs, inner };
                    }
                }
            }
            "xargs" => {
                via_xargs = true;
                i = skip_opts(
                    words,
                    i + 1,
                    &[
                        "-I", "-n", "-P", "-d", "-L", "-s", "-a", "-E", "--max-args", "--max-procs",
                        "--delimiter", "--arg-file", "--max-lines", "--max-chars", "--eof",
                    ],
                );
            }
            "watch" => {
                let j = skip_opts(words, i + 1, &["-n", "--interval"]);
                if j < words.len() {
                    inner.push(words[j..].join(" "));
                }
                return Invocation { argv: Vec::new(), via_xargs, inner };
            }
            "su" | "runuser" => {
                let mut j = i + 1;
                while j < words.len() {
                    let w = words[j].as_str();
                    if w == "-c" || w == "--command" || w == "--session-command" {
                        if let Some(s) = words.get(j + 1) {
                            inner.push(s.clone());
                        }
                        break;
                    }
                    if let Some(s) = w.strip_prefix("--command=") {
                        inner.push(s.to_string());
                        break;
                    }
                    if p == "runuser" && (w == "-u" || w == "--user") {
                        let mut k = j + 2;
                        if words.get(k).map(|x| x == "--").unwrap_or(false) {
                            k += 1;
                        }
                        let argv = words.get(k..).map(|s| s.to_vec()).unwrap_or_default();
                        return Invocation { argv, via_xargs, inner };
                    }
                    j += 1;
                }
                return Invocation { argv: Vec::new(), via_xargs, inner };
            }
            "systemd-run" => {
                let mut j = i + 1;
                const VALUE: &[&str] = &[
                    "-u", "--unit", "-p", "--property", "-E", "--setenv", "--uid", "--gid", "--nice",
                    "--working-directory", "-M", "--machine", "--description", "--slice", "-H",
                    "--host", "--on-active", "--on-calendar", "--on-boot", "--on-startup",
                    "--on-unit-active", "--on-unit-inactive", "--timer-property",
                ];
                while j < words.len() {
                    let w = words[j].as_str();
                    if w == "--" {
                        j += 1;
                        break;
                    }
                    if !w.starts_with('-') {
                        break;
                    }
                    j += if VALUE.contains(&w) { 2 } else { 1 };
                }
                i = j;
            }
            _ => break,
        }
    }
    let argv = words.get(i..).map(|s| s.to_vec()).unwrap_or_default();
    Invocation { argv, via_xargs, inner }
}

/// Quote a word for display / re-parsing by the policy shell parser.
pub fn shell_quote(w: &str) -> String {
    if !w.is_empty()
        && w.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
    {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', r"'\''"))
    }
}
