//! Program rules: file deletion/moves/permissions, find, rsync, shells, interpreters, eval.

use super::paths::*;
use super::{Ctx, Policy, Verdict, DECODE_RE, FETCH_RE, PIPE_DECODE_MSG, PIPE_FETCH_MSG, SELF_MSG};
use crate::config;

pub(crate) const SHELLS: &[&str] =
    &["sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "rbash", "fish", "csh", "tcsh"];

/// Programs that may mention MySSH-MCP's own paths because they only read (or are checked elsewhere).
const SELF_READ_OK: &[&str] = &[
    "cat", "tac", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "zcat", "rg",
    "ls", "stat", "wc", "file", "du", "df", "md5sum", "sha1sum", "sha256sum", "sha512sum", "b2sum",
    "diff", "cmp", "strings", "journalctl", "readlink", "realpath", "namei", "lsattr", "getfacl",
    "nl", "sort", "uniq", "cut", "jq", "column", "od", "xxd", "hexdump", "test", "[", "echo",
    "printf", "tree", "basename", "dirname", "pwd", "which", "whereis", "type", "find", "cp",
    "systemctl", "service", "myssh-mcp",
];

const FIND_DESTRUCTIVE: &[&str] = &["rm", "shred", "unlink", "truncate", "dd", "mv", "rmdir"];
const FIND_FILTERS: &[&str] = &[
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-mtime",
    "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-newer", "-size", "-user", "-group", "-perm",
    "-empty", "-uid", "-gid", "-inum", "-samefile", "-links", "-nouser", "-nogroup", "-lname",
    "-ilname",
];
const FIND_DELETE_FORBIDDEN_ROOTS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/proc", "/sbin", "/sys",
    "/usr", "/var",
];

// ---------------------------------------------------------------------------- argument helpers

pub(crate) struct Args<'a> {
    pub flags: Vec<&'a str>,
    pub pos: Vec<&'a str>,
}

impl Args<'_> {
    pub fn short(&self, ch: char) -> bool {
        self.flags.iter().any(|f| !f.starts_with("--") && f[1..].contains(ch))
    }
    pub fn long(&self, name: &str) -> bool {
        let with_eq = format!("{name}=");
        self.flags.iter().any(|f| *f == name || f.starts_with(&with_eq))
    }
}

/// Split argv into flags and positionals. Values of `value_opts` are skipped (neither).
pub(crate) fn split_args<'a>(args: &'a [String], value_opts: &[&str]) -> Args<'a> {
    let mut flags = Vec::new();
    let mut pos = Vec::new();
    let mut i = 0;
    let mut end = false;
    while i < args.len() {
        let a = args[i].as_str();
        if end {
            pos.push(a);
            i += 1;
            continue;
        }
        if a == "--" {
            end = true;
            i += 1;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            flags.push(a);
            i += if value_opts.contains(&a) { 2 } else { 1 };
            continue;
        }
        pos.push(a);
        i += 1;
    }
    Args { flags, pos }
}

/// Value of `-x VALUE` / `--long VALUE` / `--long=VALUE`.
pub(crate) fn opt_value<'a>(args: &'a [String], names: &[&str]) -> Option<&'a str> {
    for (i, a) in args.iter().enumerate() {
        for n in names {
            if a == n {
                return args.get(i + 1).map(|s| s.as_str());
            }
            if n.starts_with("--") {
                if let Some(v) = a.strip_prefix(&format!("{n}=")) {
                    return Some(v);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------- shells

pub(crate) enum ShellMode {
    Command(String),
    Script(String),
    Stdin,
}

pub(crate) fn shell_mode(args: &[String]) -> ShellMode {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if (a.starts_with('-') || a.starts_with('+')) && a.len() > 1 {
            if matches!(a, "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file") {
                i += 2;
                continue;
            }
            if !a.starts_with("--") && a[1..].contains('c') {
                let mut j = i + 1;
                while j < args.len() && args[j].starts_with('-') && args[j].len() > 1 {
                    j += 1;
                }
                return match args.get(j) {
                    Some(s) => ShellMode::Command(s.clone()),
                    None => ShellMode::Stdin,
                };
            }
            if a == "-s" {
                return ShellMode::Stdin;
            }
            i += 1;
            continue;
        }
        break;
    }
    match args.get(i) {
        Some(s) if s != "-" => ShellMode::Script(s.clone()),
        _ => ShellMode::Stdin,
    }
}

pub(crate) fn is_interpreter(p: &str) -> bool {
    p.starts_with("python")
        || matches!(p, "perl" | "ruby" | "node" | "nodejs" | "php" | "lua" | "Rscript" | "deno" | "bun")
}

/// The program executes code it reads from stdin (`... | bash`, `... | python3`).
pub(crate) fn reads_stdin_as_code(prog: &str, args: &[String]) -> bool {
    if SHELLS.contains(&prog) {
        return matches!(shell_mode(args), ShellMode::Stdin);
    }
    if is_interpreter(prog) {
        return args.iter().all(|a| a.starts_with('-'));
    }
    false
}

fn safe_chmod_mode(mode: &str) -> bool {
    if !(mode.len() == 3 || mode.len() == 4) || !mode.chars().all(|c| ('0'..='7').contains(&c)) {
        return false;
    }
    let d: Vec<u32> = mode.chars().rev().take(3).filter_map(|c| c.to_digit(8)).collect();
    // d[0] = other, d[1] = group, d[2] = owner
    d.len() == 3 && d[0] & 2 == 0 && d[1] & 2 == 0 && d[2] & 4 != 0
}

impl Policy {
    /// Dispatch to the rule for this program.
    pub(crate) fn check_program(&self, c: &Ctx) -> Verdict {
        self.check_self_refs(c)?;
        if c.exe.contains('/') {
            if let Some(n) = normalize(c.exe, c.cwd) {
                self.check_executable_script(&n, c)?;
            }
        }
        let p = c.prog;
        match p {
            "rm" => self.rule_rm(c),
            "rmdir" | "unlink" => {
                let a = split_args(c.args, &[]);
                for t in &a.pos {
                    self.check_destroy(t, c.cwd, false, p)?;
                }
                Ok(())
            }
            "shred" => {
                let a = split_args(c.args, &["-n", "-s", "--iterations", "--size"]);
                for t in &a.pos {
                    if let Some(n) = normalize(t, c.cwd) {
                        self.check_overwrite_target(&n, "shred")?;
                    }
                    self.check_destroy(t, c.cwd, false, "shred")?;
                }
                Ok(())
            }
            "mv" => self.rule_mv(c),
            "cp" | "install" | "ln" => self.rule_copy(c),
            "dd" => {
                for a in c.args {
                    if let Some(v) = a.strip_prefix("of=") {
                        for t in expand_braces(v) {
                            if let Some(n) = normalize(&t, c.cwd) {
                                self.check_overwrite_target(&n, "dd")?;
                            }
                        }
                    }
                }
                Ok(())
            }
            "tee" | "truncate" => {
                let a = split_args(c.args, &["-s", "--size", "-r", "--reference"]);
                for t in &a.pos {
                    for e in expand_braces(t) {
                        if let Some(n) = normalize(&e, c.cwd) {
                            self.check_overwrite_target(&n, p)?;
                        }
                    }
                }
                Ok(())
            }
            "chmod" | "chown" | "chgrp" | "chattr" | "setfacl" => self.rule_perms(c),
            "find" => self.rule_find(c),
            "rsync" => self.rule_rsync(c),
            "eval" => self.rule_eval(c),
            "source" | "." => match c.args.first() {
                Some(s) => self.check_script_ref(s, c),
                None => Ok(()),
            },
            "myssh-mcp" => match c.args.first().map(|s| s.as_str()) {
                Some("check") | Some("check-sql") | Some("--version") | Some("-V") | Some("--help")
                | Some("-h") | Some("help") => Ok(()),
                other => Err(format!(
                    "`myssh-mcp {}` can only be run by the server owner (it could rotate the API key or change the service)",
                    other.unwrap_or("")
                )),
            },
            _ if SHELLS.contains(&p) => self.rule_shell(c),
            _ if is_interpreter(p) => self.rule_interpreter(c),
            _ => self.check_program_sys(c),
        }
    }

    fn check_self_refs(&self, c: &Ctx) -> Verdict {
        if SELF_READ_OK.contains(&c.prog) {
            return Ok(());
        }
        for a in c.args {
            if self.self_paths.iter().any(|s| a.contains(s.as_str())) {
                return Err(format!("`{}` touching `{a}`: {SELF_MSG}", c.prog));
            }
            if !a.starts_with('-') {
                if let Some(n) = normalize(a, c.cwd) {
                    if self.self_touch(&n) {
                        return Err(format!("`{}` touching `{a}`: {SELF_MSG}", c.prog));
                    }
                }
            }
        }
        Ok(())
    }

    fn rule_rm(&self, c: &Ctx) -> Verdict {
        let a = split_args(c.args, &[]);
        if a.long("--no-preserve-root") {
            return Err("`rm --no-preserve-root` is never allowed".into());
        }
        let recursive = a.short('r') || a.short('R') || a.long("--recursive");
        if recursive && c.via_xargs {
            return Err("`xargs rm -r` deletes targets that cannot be inspected — pass explicit paths to rm".into());
        }
        let verb = if recursive { "rm -r" } else { "rm" };
        for t in &a.pos {
            self.check_destroy(t, c.cwd, recursive, verb)?;
        }
        Ok(())
    }

    fn rule_mv(&self, c: &Ctx) -> Verdict {
        let a = split_args(c.args, &["-t", "--target-directory", "-S", "--suffix"]);
        let tdir = opt_value(c.args, &["-t", "--target-directory"]);
        let (sources, dest): (Vec<&str>, Option<&str>) = match tdir {
            Some(t) => (a.pos.clone(), Some(t)),
            None if a.pos.len() >= 2 => (a.pos[..a.pos.len() - 1].to_vec(), a.pos.last().copied()),
            None => (a.pos.clone(), None),
        };
        for s in sources {
            self.check_move_source(s, c.cwd)?;
        }
        if let Some(d) = dest {
            for t in expand_braces(d) {
                if let Some(n) = normalize(&t, c.cwd) {
                    if n == "/dev/null" {
                        return Err("`mv ... /dev/null` destroys data".into());
                    }
                    self.check_overwrite_target(&n, "mv")?;
                }
            }
        }
        Ok(())
    }

    fn check_move_source(&self, raw: &str, cwd: Option<&str>) -> Verdict {
        for t in expand_braces(raw) {
            if has_dynamic(&t) {
                continue;
            }
            let Some(n) = normalize(&t, cwd) else { continue };
            let (prefix, glob) = glob_prefix(&n);
            if self.self_destroy(&prefix) || self.self_glob_hit(&n) {
                return Err(format!("`mv {t}`: {SELF_MSG}"));
            }
            match glob {
                Some(g) => {
                    let wide = is_bare_wildcard(&g)
                        && (depth(&prefix) <= 1 || self.protected_dirs.iter().any(|d| *d == prefix));
                    if wide {
                        return Err(format!("`mv {t}` would move every file out of `{prefix}`"));
                    }
                }
                None => {
                    if depth(&n) <= 1 {
                        return Err(format!("moving the top-level path `{n}` is blocked"));
                    }
                    if let Some(d) = self.protected_dir_hit(&n) {
                        return Err(format!("moving `{n}` would relocate protected directory `{d}`"));
                    }
                    if let Some(f) = self.protected_file_hit(&n, false) {
                        return Err(format!("moving protected file `{f}` is blocked"));
                    }
                }
            }
        }
        Ok(())
    }

    fn rule_copy(&self, c: &Ctx) -> Verdict {
        let a = split_args(
            c.args,
            &["-t", "--target-directory", "-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group"],
        );
        let dest = opt_value(c.args, &["-t", "--target-directory"])
            .or_else(|| if a.pos.len() >= 2 { a.pos.last().copied() } else { None });
        if let Some(d) = dest {
            if self.self_paths.iter().any(|s| d.contains(s.as_str())) {
                return Err(format!("`{}` into `{d}`: {SELF_MSG}", c.prog));
            }
            for t in expand_braces(d) {
                if let Some(n) = normalize(&t, c.cwd) {
                    self.check_overwrite_target(&n, c.prog)?;
                }
            }
        }
        Ok(())
    }

    fn rule_perms(&self, c: &Ctx) -> Verdict {
        let value_opts: &[&str] = match c.prog {
            "setfacl" => &[
                "-m", "-x", "-M", "-X", "--set", "--set-file", "--modify", "--remove",
                "--modify-file", "--remove-file",
            ],
            "chattr" => &["-v", "-p"],
            _ => &[],
        };
        let a = split_args(c.args, value_opts);
        let recursive = a.short('R') || a.long("--recursive");
        let mut mode: Option<&str> = None;
        let targets: Vec<&str> = match c.prog {
            "chattr" => a.pos.iter().copied().filter(|p| !p.starts_with('+') && !p.starts_with('=')).collect(),
            "setfacl" => a.pos.clone(),
            _ => {
                let reference = a.flags.iter().any(|f| f.starts_with("--reference"));
                let mode_in_flags = c.prog == "chmod"
                    && a.flags.iter().any(|f| {
                        !f.starts_with("--") && f.len() > 1 && f[1..].chars().all(|ch| "rwxXst".contains(ch))
                    });
                if reference || mode_in_flags {
                    a.pos.clone()
                } else {
                    mode = a.pos.first().copied();
                    a.pos.iter().copied().skip(1).collect()
                }
            }
        };
        for t in targets {
            for e in expand_braces(t) {
                let e = e.as_str();
                if has_dynamic(e) {
                    if recursive {
                        return Err(format!("`{} -R {e}`: a variable target could expand to `/`", c.prog));
                    }
                    continue;
                }
                let Some(n) = normalize(e, c.cwd) else {
                    if recursive {
                        return Err(format!(
                            "`{} -R {e}` on a relative path while the working directory is unknown",
                            c.prog
                        ));
                    }
                    continue;
                };
                let (prefix, glob) = glob_prefix(&n);
                if self.self_destroy(&prefix) || self.self_glob_hit(&n) {
                    return Err(format!("`{}` on `{e}`: {SELF_MSG}", c.prog));
                }
                let wide = recursive || glob.as_deref().map(is_bare_wildcard).unwrap_or(false);
                if wide {
                    if depth(&prefix) <= 1 {
                        return Err(format!("`{} -R` on top-level directory `{prefix}` is blocked", c.prog));
                    }
                    if let Some(d) = CORE_SYSTEM_DIRS.iter().find(|d| **d == prefix || is_ancestor(&prefix, d)) {
                        return Err(format!(
                            "`{} -R {e}` would change permissions/ownership of system directory `{d}` (breaks sudo/ssh)",
                            c.prog
                        ));
                    }
                }
                if glob.is_none() && CORE_SYSTEM_DIRS.contains(&n.as_str()) {
                    return Err(format!("changing permissions/ownership of system directory `{n}` is blocked"));
                }
                if let Some(f) = self.protected_file_hit(&n, glob.is_some()) {
                    let tightening = c.prog == "chmod" && mode.map(safe_chmod_mode).unwrap_or(false);
                    if !tightening {
                        return Err(format!(
                            "`{}` on protected file `{f}` is blocked (only safe chmod modes like 600/644 are allowed)",
                            c.prog
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn rule_find(&self, c: &Ctx) -> Verdict {
        let args = c.args;
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if matches!(a, "-H" | "-L" | "-P") || a.starts_with("-O") {
                i += 1;
            } else if a == "-D" {
                i += 2;
            } else {
                break;
            }
        }
        let mut starts: Vec<&str> = Vec::new();
        while i < args.len() && !args[i].starts_with('-') && args[i] != "(" && args[i] != "!" {
            starts.push(args[i].as_str());
            i += 1;
        }
        if starts.is_empty() {
            starts.push(".");
        }
        let rest = &args[i.min(args.len())..];
        let mut deletes = rest.iter().any(|a| a == "-delete");
        let mut exec_mutates = false;
        let mut k = 0;
        while k < rest.len() {
            let a = rest[k].as_str();
            if matches!(a, "-exec" | "-execdir" | "-ok" | "-okdir") {
                let mut j = k + 1;
                let mut words: Vec<String> = Vec::new();
                while j < rest.len() && rest[j] != ";" && rest[j] != "+" {
                    words.push(rest[j].replace("{}", "/tmp/__find_match__"));
                    j += 1;
                }
                if let Some(p0) = words.first() {
                    let b = basename(p0);
                    if FIND_DESTRUCTIVE.contains(&b) {
                        deletes = true;
                    }
                    if !SELF_READ_OK.contains(&b) || b == "cp" {
                        exec_mutates = true;
                    }
                }
                let joined: Vec<String> = words.iter().map(|w| super::shell_quote(w)).collect();
                self.check_shell(&joined.join(" "), c.cwd.map(String::from), c.depth + 1)?;
                k = j + 1;
                continue;
            }
            if matches!(a, "-fprint" | "-fprint0" | "-fprintf" | "-fls") {
                if let Some(n) = rest.get(k + 1).and_then(|v| normalize(v, c.cwd)) {
                    self.check_overwrite_target(&n, "find -fprint")?;
                }
            }
            k += 1;
        }
        if !(deletes || exec_mutates) {
            return Ok(());
        }
        let filtered = rest.iter().any(|a| FIND_FILTERS.contains(&a.as_str()));
        for s in starts {
            for e in expand_braces(s) {
                if has_dynamic(&e) {
                    return Err(format!("`find {e} ... -delete/-exec` with a variable start path cannot be inspected"));
                }
                let Some(n) = normalize(&e, c.cwd) else {
                    return Err(format!("`find {e} ... -delete/-exec` while the working directory is unknown"));
                };
                let (prefix, _) = glob_prefix(&n);
                if self.self_destroy(&prefix) {
                    return Err(format!("`find {e}` with -delete/-exec: {SELF_MSG}"));
                }
                if deletes {
                    if FIND_DELETE_FORBIDDEN_ROOTS.contains(&prefix.as_str()) {
                        return Err(format!("`find {prefix} ... -delete` over a system root is blocked — narrow the start path"));
                    }
                    if !filtered {
                        if depth(&prefix) <= 1 {
                            return Err(format!("`find {prefix} -delete` without filters would wipe a top-level directory"));
                        }
                        if let Some(d) = self.protected_dir_hit(&prefix) {
                            return Err(format!("`find {e} -delete` without filters would wipe protected directory `{d}`"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn rule_rsync(&self, c: &Ctx) -> Verdict {
        let deleting = c.args.iter().any(|a| a.starts_with("--delete") || a == "--remove-source-files");
        let a = split_args(
            c.args,
            &[
                "-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--files-from",
                "--exclude-from", "--include-from", "--log-file", "--password-file", "--chmod",
                "--chown", "--rsync-path", "--backup-dir", "--suffix", "--partial-dir", "--temp-dir",
                "-T", "--compare-dest", "--copy-dest", "--link-dest", "--port", "--bwlimit",
                "--timeout", "--max-size", "--min-size", "--max-delete", "--out-format", "--info",
                "--debug", "--iconv",
            ],
        );
        if a.pos.len() < 2 {
            return Ok(());
        }
        let dest = a.pos[a.pos.len() - 1];
        let remote = dest.contains("::")
            || dest.starts_with("rsync://")
            || dest.split('/').next().map(|first| first.contains(':')).unwrap_or(false);
        if remote {
            return Ok(());
        }
        if let Some(n) = normalize(dest, c.cwd) {
            if (deleting && self.self_destroy(&n)) || self.self_touch(&n) {
                return Err(format!("`rsync` into `{n}`: {SELF_MSG}"));
            }
            if deleting {
                if depth(&n) <= 1 {
                    return Err(format!("`rsync --delete` into top-level directory `{n}` is blocked"));
                }
                if let Some(d) = self.protected_dir_hit(&n) {
                    return Err(format!("`rsync --delete` into `{n}` could wipe protected directory `{d}`"));
                }
            }
            self.check_overwrite_target(&n, "rsync")?;
        }
        Ok(())
    }

    fn rule_shell(&self, c: &Ctx) -> Verdict {
        match shell_mode(c.args) {
            ShellMode::Command(s) => {
                self.check_raw(&s)?;
                self.check_shell(&s, c.cwd.map(String::from), c.depth + 1)
            }
            ShellMode::Script(p) => self.check_script_ref(&p, c),
            ShellMode::Stdin => Ok(()),
        }
    }

    fn check_script_ref(&self, p: &str, c: &Ctx) -> Verdict {
        if p.starts_with("<(") {
            if DECODE_RE.is_match(p) {
                return Err(PIPE_DECODE_MSG.into());
            }
            if FETCH_RE.is_match(p) && !self.allow_remote_script_pipe {
                return Err(PIPE_FETCH_MSG.into());
            }
            return Ok(());
        }
        match normalize(p, c.cwd) {
            Some(n) => self.check_script_file(&n, c, true),
            None => Ok(()),
        }
    }

    /// Inspect a script file that is about to be executed.
    fn check_script_file(&self, path: &str, c: &Ctx, is_shell: bool) -> Verdict {
        if path.contains(config::API_KEY_FILE_MARKER) {
            return Err(SELF_MSG.into());
        }
        let Ok(meta) = std::fs::metadata(path) else { return Ok(()) };
        if !meta.is_file() || meta.len() > 2 * 1024 * 1024 {
            return Ok(());
        }
        let Ok(bytes) = std::fs::read(path) else { return Ok(()) };
        let text = String::from_utf8_lossy(&bytes);
        let wrap = |e: String| format!("script `{path}`: {e}");
        self.check_raw(&text).map_err(wrap)?;
        if is_shell {
            self.check_shell(&text, c.cwd.map(String::from), c.depth + 1).map_err(wrap)?;
        }
        Ok(())
    }

    /// `./deploy.sh` / `/opt/x/run`: inspect the file when it is a `#!` script.
    fn check_executable_script(&self, path: &str, c: &Ctx) -> Verdict {
        use std::io::Read;
        let mut head = [0u8; 256];
        let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) {
            Ok(n) => n,
            Err(_) => return Ok(()),
        };
        if n < 2 || &head[..2] != b"#!" {
            return Ok(());
        }
        let first_line = String::from_utf8_lossy(&head[..n]).lines().next().unwrap_or("").to_string();
        let is_shell = SHELLS.iter().any(|s| {
            first_line.ends_with(&format!("/{s}"))
                || first_line.contains(&format!("/{s} "))
                || first_line.contains(&format!("env {s}"))
        });
        self.check_script_file(path, c, is_shell)
    }

    fn rule_interpreter(&self, c: &Ctx) -> Verdict {
        // Inline code (-c / -e) is already covered by the raw scan of the full command.
        let inline = c.args.iter().any(|a| {
            matches!(a.as_str(), "-c" | "-e" | "-E" | "-r" | "-m" | "--eval" | "-p" | "--print")
        });
        if inline {
            return Ok(());
        }
        if let Some(script) = c.args.iter().find(|a| !a.starts_with('-')) {
            if let Some(n) = normalize(script, c.cwd) {
                self.check_script_file(&n, c, false)?;
            }
        }
        Ok(())
    }

    fn rule_eval(&self, c: &Ctx) -> Verdict {
        let joined = c.args.join(" ");
        if joined.contains("$(") || joined.contains('`') {
            if DECODE_RE.is_match(&joined) {
                return Err(PIPE_DECODE_MSG.into());
            }
            if FETCH_RE.is_match(&joined) && !self.allow_remote_script_pipe {
                return Err(PIPE_FETCH_MSG.into());
            }
            return Ok(());
        }
        self.check_raw(&joined)?;
        self.check_shell(&joined, c.cwd.map(String::from), c.depth + 1)
    }
}
