//! Configuration file (`/etc/myssh-mcp/config.toml`) and well-known paths.

use serde::{Deserialize, Serialize};

pub const CONFIG_DIR: &str = "/etc/myssh-mcp";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/myssh-mcp/config.toml";
pub const DEFAULT_LOG_FILE: &str = "/server_log/claude_log.txt";
pub const API_KEY_FILE: &str = "/home/MCP_MySSH_APIKey.txt";
pub const API_KEY_FILE_MARKER: &str = "MCP_MySSH_APIKey";
pub const BINARY_PATH: &str = "/usr/local/bin/myssh-mcp";
pub const SERVICE_NAME: &str = "myssh-mcp";
pub const UNIT_PATH: &str = "/etc/systemd/system/myssh-mcp.service";
pub const LOGROTATE_PATH: &str = "/etc/logrotate.d/myssh-mcp";
pub const BACKUP_DIR: &str = "/var/backups/myssh-mcp";
pub const DEFAULT_PORT: u16 = 8765;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    pub limits: LimitsConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Address to listen on. Use 127.0.0.1 when running behind a reverse proxy / SSH tunnel.
    pub bind: String,
    pub port: u16,
    /// SHA-256 (hex) of the API key. The plain key is only stored in /home/MCP_MySSH_APIKey.txt.
    pub api_key_sha256: String,
    /// Trust X-Forwarded-For / X-Real-IP (only enable behind your own reverse proxy).
    pub trust_proxy: bool,
    /// Public URL shown in the connection guide (informational only).
    pub public_url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            port: DEFAULT_PORT,
            api_key_sha256: String::new(),
            trust_proxy: false,
            public_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub log_file: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { log_file: DEFAULT_LOG_FILE.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub default_timeout_secs: u64,
    pub max_timeout_secs: u64,
    pub max_output_bytes: usize,
    pub max_read_bytes: usize,
    pub max_concurrent_commands: usize,
    pub default_cwd: String,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            default_timeout_secs: 120,
            max_timeout_secs: 1800,
            max_output_bytes: 512 * 1024,
            max_read_bytes: 1024 * 1024,
            max_concurrent_commands: 8,
            default_cwd: "/root".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub allow_reboot: bool,
    pub allow_remote_script_pipe: bool,
    pub allow_destructive_sql: bool,
    pub allow_privileged_containers: bool,
    pub protected_dirs: Vec<String>,
    pub protected_files: Vec<String>,
    pub protected_services: Vec<String>,
    pub critical_packages: Vec<String>,
    pub extra_deny_patterns: Vec<String>,
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allow_reboot: false,
            allow_remote_script_pipe: false,
            allow_destructive_sql: false,
            allow_privileged_containers: false,
            protected_dirs: strings(&[
                "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/libx32",
                "/opt", "/proc", "/root", "/run", "/sbin", "/snap", "/srv", "/sys", "/usr", "/var",
                "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/local", "/usr/local/bin",
                "/usr/share", "/usr/include", "/var/lib", "/var/log", "/var/backups", "/var/spool",
                "/var/mail", "/var/lib/docker", "/var/lib/containerd", "/var/lib/mysql",
                "/var/lib/postgresql", "/var/lib/redis", "/var/lib/mongodb", "/var/lib/dpkg",
                "/var/lib/apt", "/etc/ssh", "/etc/systemd", "/etc/nginx", "/etc/apache2",
                "/etc/mysql", "/etc/postgresql", "/etc/docker", "/etc/netplan", "/etc/network",
                "/etc/apt", "/etc/ssl", "/etc/letsencrypt", "/etc/sudoers.d", "/etc/pam.d",
                "/etc/security", "/root/.ssh", "/boot/efi", "/boot/grub",
            ]),
            protected_files: strings(&[
                "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
                "/etc/fstab", "/etc/crypttab", "/etc/default/grub", "/etc/ssh/sshd_config",
                "/etc/ssh/sshd_config.d/", "/etc/sudoers.d/", "/etc/netplan/", "/etc/pam.d/",
                "/boot/", "authorized_keys",
            ]),
            protected_services: strings(&[
                "ssh", "sshd", "ssh.socket", "systemd-journald", "systemd-logind",
                "systemd-networkd", "systemd-resolved", "systemd-udevd", "networking",
                "NetworkManager", "dbus",
            ]),
            critical_packages: strings(&[
                "openssh-server", "openssh-client", "openssh-sftp-server", "systemd", "systemd-sysv",
                "libc6", "libc-bin", "bash", "dash", "coreutils", "dpkg", "apt", "sudo", "login",
                "passwd", "util-linux", "mount", "init", "base-files", "base-passwd", "grub-pc",
                "grub-efi-amd64", "grub-efi-amd64-signed", "grub-common", "grub2-common",
                "linux-generic", "linux-image-generic", "linux-image-virtual", "linux-virtual",
                "netplan.io", "iproute2", "ifupdown", "network-manager", "systemd-resolved",
                "python3", "perl-base", "tar", "gzip", "findutils", "grep", "sed",
                "ca-certificates", "cloud-init",
            ]),
            extra_deny_patterns: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {path}: {e}"))?;
        toml::from_str(&text).map_err(|e| format!("invalid config {path}: {e}"))
    }

    /// Load the config or fall back to built-in defaults when the file does not exist.
    pub fn load_or_default(path: &str) -> Result<Config, String> {
        if std::path::Path::new(path).exists() {
            Config::load(path)
        } else {
            Ok(Config::default())
        }
    }
}

fn q(s: &str) -> String {
    // JSON string escaping is a valid TOML basic string.
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn list(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    let mut out = String::from("[\n");
    for it in items {
        out.push_str("    ");
        out.push_str(&q(it));
        out.push_str(",\n");
    }
    out.push(']');
    out
}

/// Render the configuration as a commented TOML document.
pub fn render_config(c: &Config) -> String {
    let s = &c.server;
    let l = &c.limits;
    let p = &c.policy;
    format!(
        r#"# =====================================================================
#  MySSH-MCP configuration
#  After editing:  sudo systemctl restart myssh-mcp
#  Test a command against the policy:  sudo myssh-mcp check "rm -rf /"
# =====================================================================

[server]
# 0.0.0.0 = reachable from the internet (protected by the API key).
# Use 127.0.0.1 if you put a TLS reverse proxy (Caddy/nginx) or an SSH tunnel in front.
bind = {bind}
port = {port}
# SHA-256 of the API key. The plain key lives in /home/MCP_MySSH_APIKey.txt.
# Rotate with:  sudo myssh-mcp rotate-key
api_key_sha256 = {hash}
# Only enable when running behind your own reverse proxy.
trust_proxy = {trust_proxy}
public_url = {public_url}

[logging]
# Every command (GRANTED / DENIED / RESULT) is appended here with an exact timestamp.
log_file = {log_file}

[limits]
default_timeout_secs = {dt}
max_timeout_secs = {mt}
max_output_bytes = {mo}
max_read_bytes = {mr}
max_concurrent_commands = {mc}
default_cwd = {cwd}

[policy]
# Built-in protections that can NOT be disabled: MySSH-MCP's own files/service,
# fork bombs, disk formatting/wiping, recursive deletes of /, ., .., *, ~ and top-level dirs.

# Allow shutdown / reboot / poweroff.
allow_reboot = {allow_reboot}
# Allow `curl ... | bash` style installers.
allow_remote_script_pipe = {allow_pipe}
# Allow DROP DATABASE/TABLE, TRUNCATE, DELETE/UPDATE without WHERE, FLUSHALL.
allow_destructive_sql = {allow_sql}
# Allow `docker run --privileged`.
allow_privileged_containers = {allow_priv}

# Directories that may not be deleted / moved / chmod -R'ed (nor any of their parents).
protected_dirs = {dirs}

# Files that may not be deleted, overwritten or moved.
#   "/abs/path"  exact file      "/abs/dir/"  everything inside      "name"  any file with that name
protected_files = {files}

# Services that may not be stopped / disabled / masked / killed.
protected_services = {services}

# Packages that may not be removed / purged.
critical_packages = {packages}

# Extra regular expressions; any command matching one of them is denied.
# Example: extra_deny_patterns = ["(?i)\\bnmap\\b", "docker\\s+rm"]
extra_deny_patterns = {extra}
"#,
        bind = q(&s.bind),
        port = s.port,
        hash = q(&s.api_key_sha256),
        trust_proxy = s.trust_proxy,
        public_url = q(&s.public_url),
        log_file = q(&c.logging.log_file),
        dt = l.default_timeout_secs,
        mt = l.max_timeout_secs,
        mo = l.max_output_bytes,
        mr = l.max_read_bytes,
        mc = l.max_concurrent_commands,
        cwd = q(&l.default_cwd),
        allow_reboot = p.allow_reboot,
        allow_pipe = p.allow_remote_script_pipe,
        allow_sql = p.allow_destructive_sql,
        allow_priv = p.allow_privileged_containers,
        dirs = list(&p.protected_dirs),
        files = list(&p.protected_files),
        services = list(&p.protected_services),
        packages = list(&p.critical_packages),
        extra = list(&p.extra_deny_patterns),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_config_round_trips() {
        let mut c = Config::default();
        c.server.api_key_sha256 = "abc".into();
        c.policy.extra_deny_patterns = vec![r"(?i)\bnmap\b".into()];
        let text = render_config(&c);
        let back: Config = toml::from_str(&text).expect("valid toml");
        assert_eq!(back.server.api_key_sha256, "abc");
        assert_eq!(back.server.port, DEFAULT_PORT);
        assert_eq!(back.policy.protected_dirs, c.policy.protected_dirs);
        assert_eq!(back.policy.extra_deny_patterns, c.policy.extra_deny_patterns);
    }
}
