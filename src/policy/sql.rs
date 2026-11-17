//! SQL statement guard (MySQL / MariaDB / PostgreSQL / SQLite).
//!
//! * `check_sql_hard`   — always blocked: shell escapes, COPY ... PROGRAM, INTO OUTFILE,
//!                         SHUTDOWN, dropping/locking the root account.
//! * `sql_destructive`  — DROP / TRUNCATE / DELETE or UPDATE without WHERE. Through the
//!                         `database_query` tool these run only after an automatic backup.
//! * `sql_is_read_only` — decides whether a query needs a backup at all.

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
static RE_WRITE_KW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:INSERT|UPDATE|DELETE|MERGE|INTO|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|CALL|LOCK|COPY|SETVAL|NEXTVAL)\b")
        .unwrap()
});
static RE_DROP_DB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bDROP\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?[`"]?([A-Za-z0-9_$-]+)"#).unwrap()
});

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
        if (ch == '-' && c.get(i + 1) == Some(&'-')) || ch == '#' {
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

/// Upper-cased statements with comments and literals removed.
fn statements(sql: &str) -> Vec<String> {
    collapse_ws(&strip_sql(sql).to_uppercase())
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The data-destroying part of `sql`, if any.
pub fn sql_destructive(sql: &str) -> Option<String> {
    for s in statements(sql) {
        if let Some(m) = RE_DROP.find(&s) {
            return Some(format!("`{}` destroys data", m.as_str()));
        }
        if RE_TRUNCATE.is_match(&s) {
            return Some("TRUNCATE wipes a whole table".into());
        }
        if RE_DELETE.is_match(&s) && !RE_WHERE.is_match(&s) {
            return Some("DELETE without WHERE wipes the whole table".into());
        }
        if RE_UPDATE_SET.is_match(&s) && !RE_WHERE.is_match(&s) {
            return Some("UPDATE without WHERE rewrites every row".into());
        }
    }
    None
}

/// True when every statement only reads data (no backup needed).
pub fn sql_is_read_only(sql: &str) -> bool {
    statements(sql).iter().all(|s| {
        let first = s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_').next().unwrap_or("");
        match first {
            "SELECT" | "WITH" | "VALUES" | "TABLE" => !RE_WRITE_KW.is_match(s),
            "SHOW" | "DESCRIBE" | "DESC" | "USE" | "HELP" => true,
            "EXPLAIN" => !(s.contains("ANALYZE") && RE_WRITE_KW.is_match(s)),
            "PRAGMA" => !s.contains('='),
            _ => false,
        }
    })
}

/// Database named in `DROP DATABASE name` (so the backup targets the right database).
pub fn dropped_database(sql: &str) -> Option<String> {
    RE_DROP_DB.captures(sql).map(|c| c[1].to_string())
}

impl Policy {
    /// SQL that is never allowed, backup or not.
    pub fn check_sql_hard(&self, sql: &str) -> Verdict {
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
        for s in statements(sql) {
            if RE_COPY_PROGRAM.is_match(&s) {
                return Err("COPY ... PROGRAM executes shell commands on the server — blocked".into());
            }
            if RE_OUTFILE.is_match(&s) {
                return Err("SELECT ... INTO OUTFILE/DUMPFILE writes files on the server — blocked".into());
            }
            if s.starts_with("SHUTDOWN") {
                return Err("SHUTDOWN stops the database server — blocked".into());
            }
        }
        if RE_ROOT_USER.is_match(&collapse_ws(&sql.to_uppercase())) {
            return Err("dropping / renaming / locking the database root account is blocked".into());
        }
        Ok(())
    }

    /// Full check used for SQL typed into shell commands (`mysql -e`, `psql -c`, `docker exec ...`):
    /// no automatic backup happens there, so destructive statements are refused.
    pub fn check_sql(&self, sql: &str) -> Verdict {
        self.check_sql_hard(sql)?;
        if !self.allow_destructive_sql {
            if let Some(reason) = sql_destructive(sql) {
                return Err(format!(
                    "{reason} — run it with the database_query tool instead: it takes an automatic backup first so the change can be reverted with database_restore"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_detection() {
        for q in [
            "SELECT * FROM users",
            "show tables",
            "DESCRIBE users",
            "EXPLAIN SELECT 1",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SELECT 'DELETE FROM x'",
            "PRAGMA table_info(users)",
            "-- just a comment\nSELECT 1;",
        ] {
            assert!(sql_is_read_only(q), "should be read-only: {q}");
        }
        for q in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1 WHERE id = 2",
            "DELETE FROM t WHERE id = 1",
            "CREATE TABLE t (id int)",
            "ALTER TABLE t ADD c int",
            "DROP TABLE t",
            "SELECT 1; DELETE FROM t WHERE id = 3",
            "EXPLAIN ANALYZE DELETE FROM t",
            "PRAGMA journal_mode=WAL",
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
        ] {
            assert!(!sql_is_read_only(q), "should be a write: {q}");
        }
    }

    #[test]
    fn destructive_detection() {
        assert!(sql_destructive("DROP TABLE users").is_some());
        assert!(sql_destructive("truncate logs").is_some());
        assert!(sql_destructive("DELETE FROM users").is_some());
        assert!(sql_destructive("UPDATE users SET admin = 1").is_some());
        assert!(sql_destructive("DELETE FROM users WHERE id = 1").is_none());
        assert!(sql_destructive("INSERT INTO t VALUES (1)").is_none());
    }

    #[test]
    fn finds_dropped_database() {
        assert_eq!(dropped_database("DROP DATABASE shop").as_deref(), Some("shop"));
        assert_eq!(dropped_database("drop database if exists `old_db`;").as_deref(), Some("old_db"));
        assert_eq!(dropped_database("DROP TABLE x"), None);
    }
}
