//! SQL statement guard (MySQL / MariaDB / PostgreSQL / SQLite).

use super::{Policy, Verdict};
use regex::Regex;
use std::sync::LazyLock;

static RE_DROP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bDROP\s+(?:DATABASE|SCHEMA|TABLE|TABLESPACE|OWNED)\b").unwrap());
static RE_TRUNCATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bTRUNCATE\b").unwrap());
static RE_DELETE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^DELETE\b|\bDELETE\s+FROM\b").unwrap());
static RE_UPDATE_SET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^UPDATE\b.*\bSET\b").unwrap());
static RE_WHERE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bWHERE\b").unwrap());
static RE_COPY_PROGRAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bCOPY\b[^;]*\bPROGRAM\b").unwrap());
static RE_OUTFILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b").unwrap());
static RE_ROOT_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:DROP|RENAME)\s+USER\b[^;]*\bROOT\b|\bALTER\s+USER\b[^;]*\bROOT\b[^;]*\bACCOUNT\s+LOCK\b").unwrap()
});
static RE_PSQL_PIPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\[og]\s*\|").unwrap());

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Remove comments and blank out the contents of string literals / quoted identifiers.
fn strip_sql(sql: &str) -> String {
    let c: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch == '-' && c.get(i + 1) == Some(&'-') || ch == '#' {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
            continue;
        }
        if ch == '\'' || ch == '"' || ch == '`' {
            let q = ch;
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    i += 2;
                    continue;
                }
                if c[i] == q {
                    if c.get(i + 1) == Some(&q) {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i += 1;
            out.push(q);
            out.push(q);
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

impl Policy {
    pub fn check_sql(&self, sql: &str) -> Verdict {
        for line in sql.lines() {
            let l = line.trim_start();
            let low = l.to_ascii_lowercase();
            if l.starts_with("\\!")
                || low.starts_with(".shell")
                || low.starts_with(".system")
                || low.starts_with("system ")
                || low.starts_with("\\system")
            {
                return Err("shell escapes from the SQL client (\\!, system, .shell) are blocked".into());
            }
        }
        if sql.contains("\\!") || RE_PSQL_PIPE.is_match(sql) {
            return Err("shell escapes from the SQL client (\\!, \\o |cmd) are blocked".into());
        }

        let cleaned = collapse_ws(&strip_sql(sql).to_uppercase());
        for stmt in cleaned.split(';') {
            let s = stmt.trim();
            if s.is_empty() {
                continue;
            }
            if RE_COPY_PROGRAM.is_match(s) {
                return Err("COPY ... PROGRAM executes shell commands on the server — blocked".into());
            }
            if RE_OUTFILE.is_match(s) {
                return Err("SELECT ... INTO OUTFILE/DUMPFILE writes files on the server — blocked".into());
            }
            if s.starts_with("SHUTDOWN") {
                return Err("SHUTDOWN stops the database server — blocked".into());
            }
            if self.allow_destructive_sql {
                continue;
            }
            if let Some(m) = RE_DROP.find(s) {
                return Err(format!(
                    "`{}` destroys data — blocked (set allow_destructive_sql = true to permit)",
                    m.as_str()
                ));
            }
            if RE_TRUNCATE.is_match(s) {
                return Err("TRUNCATE wipes a whole table — blocked (allow_destructive_sql = false)".into());
            }
            if RE_DELETE.is_match(s) && !RE_WHERE.is_match(s) {
                return Err("DELETE without WHERE wipes the whole table — add a WHERE clause".into());
            }
            if RE_UPDATE_SET.is_match(s) && !RE_WHERE.is_match(s) {
                return Err("UPDATE without WHERE rewrites every row — add a WHERE clause".into());
            }
        }
        if RE_ROOT_USER.is_match(&collapse_ws(&sql.to_uppercase())) {
            return Err("dropping / renaming / locking the database root account is blocked".into());
        }
        Ok(())
    }
}
