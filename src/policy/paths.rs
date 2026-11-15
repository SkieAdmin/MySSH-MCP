//! Lexical path helpers used by the policy engine (no filesystem access).

pub const HOME: &str = "/root";

/// Words that, as targets of a recursive delete, always wipe "everything here".
pub const ALWAYS_BAD_TARGETS: &[&str] = &[
    "/", "/*", "/.*", ".", "./", "./*", ".*", "..", "../", "../*", "*", "~", "~/", "~/*",
];

/// Core OS directories: permission/ownership changes on these (or their parents) break the system.
pub const CORE_SYSTEM_DIRS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/root",
    "/run", "/sbin", "/sys", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
    "/usr/local", "/usr/local/bin", "/usr/share", "/var", "/var/lib", "/var/log", "/etc/ssh",
    "/etc/sudoers.d", "/etc/systemd", "/etc/pam.d", "/etc/security", "/etc/ssl", "/root/.ssh",
    "/var/lib/dpkg", "/var/lib/apt", "/tmp", "/home",
];

pub fn basename(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(i) => &t[i + 1..],
        None => t,
    }
}

pub fn has_dynamic(s: &str) -> bool {
    s.contains('$') || s.contains('`')
}

pub fn is_glob_char(c: char) -> bool {
    c == '*' || c == '?' || c == '['
}

pub fn has_glob(s: &str) -> bool {
    s.chars().any(is_glob_char)
}

/// Lexically normalize `path` against `cwd`. Returns None when the path cannot be resolved
/// statically (variables, `~user`, relative path with unknown cwd).
pub fn normalize(path: &str, cwd: Option<&str>) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || has_dynamic(path) {
        return None;
    }
    let abs = if path == "~" {
        HOME.to_string()
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("{HOME}/{rest}")
    } else if path.starts_with('~') {
        return None;
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{}", cwd?, path)
    };
    let mut parts: Vec<&str> = Vec::new();
    for comp in abs.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", parts.join("/")))
    }
}

/// Number of components: "/" = 0, "/etc" = 1, "/etc/ssh" = 2.
pub fn depth(p: &str) -> usize {
    if p == "/" {
        0
    } else {
        p.trim_end_matches('/').matches('/').count()
    }
}

/// For a normalized path containing glob characters, return the directory part before the first
/// globbed component, plus the first globbed component itself.
/// `/var/*` -> ("/var", Some("*")), `/etc/passwd` -> ("/etc/passwd", None)
pub fn glob_prefix(p: &str) -> (String, Option<String>) {
    if !has_glob(p) {
        return (p.to_string(), None);
    }
    let mut parts: Vec<&str> = Vec::new();
    let mut first_glob = None;
    for comp in p.split('/').filter(|c| !c.is_empty()) {
        if has_glob(comp) {
            first_glob = Some(comp.to_string());
            break;
        }
        parts.push(comp);
    }
    let prefix = if parts.is_empty() { "/".to_string() } else { format!("/{}", parts.join("/")) };
    (prefix, first_glob)
}

/// A glob component that matches (almost) everything: `*`, `.*`, `*.*`, `?*` ...
pub fn is_bare_wildcard(comp: &str) -> bool {
    comp.chars().any(|c| c == '*' || c == '?') && comp.chars().all(|c| c == '*' || c == '?' || c == '.')
}

/// `a` is a strict ancestor directory of `b`.
pub fn is_ancestor(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    if a == "/" {
        return true;
    }
    b.starts_with(&format!("{a}/"))
}

/// `p` equals `base` or lives inside it.
pub fn is_within(p: &str, base: &str) -> bool {
    p == base || base == "/" || p.starts_with(&format!("{}/", base.trim_end_matches('/')))
}

/// Shell-style glob match (`*` and `?` do not cross `/`, `[...]` matches any one char).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_rec(&p, &t, 0)
}

fn glob_rec(p: &[char], t: &[char], depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match p.first() {
        None => t.is_empty(),
        Some('*') => {
            let mut k = 0;
            loop {
                if glob_rec(&p[1..], &t[k..], depth + 1) {
                    return true;
                }
                if k >= t.len() || t[k] == '/' {
                    return false;
                }
                k += 1;
            }
        }
        Some('?') => !t.is_empty() && t[0] != '/' && glob_rec(&p[1..], &t[1..], depth + 1),
        Some('[') => match p.iter().skip(1).position(|&c| c == ']') {
            Some(off) => !t.is_empty() && t[0] != '/' && glob_rec(&p[off + 2..], &t[1..], depth + 1),
            None => !t.is_empty() && t[0] == '[' && glob_rec(&p[1..], &t[1..], depth + 1),
        },
        Some(&c) => !t.is_empty() && t[0] == c && glob_rec(&p[1..], &t[1..], depth + 1),
    }
}

/// Bash brace expansion for `{a,b,c}` lists (sequence expressions are left untouched).
pub fn expand_braces(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    expand_into(s, &mut out);
    if out.is_empty() {
        out.push(s.to_string());
    }
    out
}

fn expand_into(s: &str, out: &mut Vec<String>) {
    if out.len() >= 64 {
        return;
    }
    let b: Vec<char> = s.chars().collect();
    for start in 0..b.len() {
        if b[start] != '{' {
            continue;
        }
        let mut depth = 0i32;
        let mut commas = Vec::new();
        let mut end = None;
        for (j, &ch) in b.iter().enumerate().skip(start) {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j);
                        break;
                    }
                }
                ',' if depth == 1 => commas.push(j),
                _ => {}
            }
        }
        if let Some(e) = end {
            if !commas.is_empty() {
                let pre: String = b[..start].iter().collect();
                let post: String = b[e + 1..].iter().collect();
                let mut bounds = vec![start];
                bounds.extend(commas);
                bounds.push(e);
                for w in bounds.windows(2) {
                    let alt: String = b[w[0] + 1..w[1]].iter().collect();
                    expand_into(&format!("{pre}{alt}{post}"), out);
                    if out.len() >= 64 {
                        return;
                    }
                }
                return;
            }
        }
    }
    out.push(s.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize("./", Some("/root")).as_deref(), Some("/root"));
        assert_eq!(normalize("../..", Some("/var/www")).as_deref(), Some("/"));
        assert_eq!(normalize("/etc/../usr//bin/", None).as_deref(), Some("/usr/bin"));
        assert_eq!(normalize("~/x", None).as_deref(), Some("/root/x"));
        assert_eq!(normalize("$HOME/x", Some("/")), None);
        assert_eq!(normalize("build", None), None);
    }

    #[test]
    fn globs() {
        assert_eq!(glob_prefix("/var/*"), ("/var".to_string(), Some("*".to_string())));
        assert_eq!(glob_prefix("/*"), ("/".to_string(), Some("*".to_string())));
        assert!(glob_match("/etc/pass*", "/etc/passwd"));
        assert!(!glob_match("/etc/*", "/etc/ssh/sshd_config"));
        assert!(glob_match("/etc/sh?dow", "/etc/shadow"));
        assert!(is_bare_wildcard("*"));
        assert!(is_bare_wildcard(".*"));
        assert!(!is_bare_wildcard("*.log"));
    }

    #[test]
    fn braces() {
        let mut v = expand_braces("/var/{log,lib}");
        v.sort();
        assert_eq!(v, vec!["/var/lib".to_string(), "/var/log".to_string()]);
        assert_eq!(expand_braces("/tmp/x"), vec!["/tmp/x".to_string()]);
        assert_eq!(expand_braces("/{a,b}/{c,d}").len(), 4);
    }

    #[test]
    fn depths() {
        assert_eq!(depth("/"), 0);
        assert_eq!(depth("/etc"), 1);
        assert_eq!(depth("/etc/ssh"), 2);
    }
}
