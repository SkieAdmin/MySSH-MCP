//! `myssh-mcp setup` / `myssh-mcp rotate-key`: API key, config, systemd unit, logrotate, key file.

use crate::auth;
use crate::config::{self, Config};
use std::path::Path;
use std::process::Command;

pub struct SetupOpts {
    pub config_path: String,
    pub bind: Option<String>,
    pub port: Option<u16>,
    pub public_host: Option<String>,
    pub new_key: bool,
    pub no_start: bool,
}

fn ensure_root_linux() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("MySSH-MCP setup only supports Linux (Ubuntu/Debian recommended)".into());
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err("must be run as root:  sudo myssh-mcp setup".into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn chmod(path: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {path}: {e}"))
}

#[cfg(not(unix))]
fn chmod(_path: &str, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn private_dir(path: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("mkdir {path}: {e}"))?;
    chmod(path, 0o700)
}

fn write_with_mode(path: &str, content: &str, mode: u32) -> Result<(), String> {
    if let Some(dir) = Path::new(path).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, content).map_err(|e| format!("write {tmp}: {e}"))?;
    chmod(&tmp, mode)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {tmp} -> {path}: {e}"))
}

fn touch_private(path: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("create {path}: {e}"))?;
    chmod(path, 0o600)
}

fn install_binary() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;
    let target = Path::new(config::BINARY_PATH);
    if let (Ok(a), Ok(b)) = (std::fs::canonicalize(&exe), std::fs::canonicalize(target)) {
        if a == b {
            return Ok(());
        }
    }
    let tmp = format!("{}.new", config::BINARY_PATH);
    std::fs::copy(&exe, &tmp).map_err(|e| format!("copy binary to {tmp}: {e}"))?;
    chmod(&tmp, 0o755)?;
    std::fs::rename(&tmp, target).map_err(|e| format!("install {}: {e}", config::BINARY_PATH))
}

fn read_key_file() -> Option<String> {
    let text = std::fs::read_to_string(config::API_KEY_FILE).ok()?;
    text.lines().find_map(|l| l.trim().strip_prefix("API_KEY=").map(|k| k.trim().to_string()))
}

/// Outbound IPv4 address of this machine (UDP "connect" sends no packets).
fn detect_host() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("1.1.1.1:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "YOUR_SERVER_IP".to_string())
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl").args(args).status().map_err(|e| format!("systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`systemctl {}` failed ({status})", args.join(" ")))
    }
}

fn ufw(args: &[&str]) -> Result<String, String> {
    let out = Command::new("ufw").args(args).output().map_err(|e| format!("ufw: {e}"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text)
    } else {
        Err(text.trim().to_string())
    }
}

/// Always add `ufw allow <port>/tcp`, whether ufw is active or not (an inactive ufw keeps the
/// rule and applies it once enabled). ufw is installed when missing but never enabled here.
fn open_firewall(port: u16) -> Result<String, String> {
    if !crate::exec::which("ufw") {
        if !crate::exec::which("apt-get") {
            return Err("ufw is not installed and apt-get is not available".into());
        }
        println!("      ufw not found — installing it (it will NOT be enabled)");
        let ok = Command::new("apt-get")
            .args(["install", "-y", "-qq", "ufw"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return Err("could not install ufw".into());
        }
    }
    let rule = format!("{port}/tcp");
    let rule_s = rule.as_str();
    ufw(&["allow", rule_s, "comment", "MySSH-MCP"]).or_else(|_| ufw(&["allow", rule_s]))?;
    let active = ufw(&["status"]).map(|s| s.contains("Status: active")).unwrap_or(false);
    Ok(if active {
        format!("ufw allow {rule} added (ufw is active — port is open)")
    } else {
        format!("ufw allow {rule} added (ufw is inactive — the rule applies as soon as ufw is enabled)")
    })
}

fn unit_text(config_path: &str) -> String {
    format!(
        "[Unit]
Description=MySSH-MCP - guarded MCP server (AI -> this server, root, audited)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart={bin} serve --config {config_path}
Restart=always
RestartSec=3
# Stop only the server on restart; jobs started by the AI (nohup ... &) keep running.
KillMode=process
LimitNOFILE=65535
WorkingDirectory=/root
Environment=HOME=/root
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
",
        bin = config::BINARY_PATH
    )
}

fn logrotate_text(log_file: &str) -> String {
    format!(
        "{log_file} {{
    weekly
    rotate 12
    maxsize 50M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}}
"
    )
}

/// `http://10.50.0.1:4040/mcp` -> `10.50.0.1:4040`
fn hostport_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split('/').next().unwrap_or(rest).to_string()
}

fn host_of(url: &str) -> String {
    let hostport = hostport_of(url);
    if let Some(stripped) = hostport.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or(stripped).to_string();
    }
    hostport.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| hostport.to_string())
}

const KEY_FILE_TEMPLATE: &str = r#"==========================================================================
  MySSH-MCP  -  API KEY & CONNECTION GUIDE
  Generated: __DATE__
==========================================================================

SERVER=__SERVER__
API_KEY=__KEY__
MCP_URL=__URL__

!! KEEP THIS FILE SECRET. The key gives (guarded) ROOT access to this server.
!! Rotate the key:        sudo myssh-mcp rotate-key
!! Audit log:             __LOG__
!! Config / safety rules: /etc/myssh-mcp/config.toml
!! Test a command:        sudo myssh-mcp check "rm -rf /"

--------------------------------------------------------------------------
 1) Claude Code (CLI)
--------------------------------------------------------------------------
claude mcp add --transport http --scope user myssh __URL__ --header "Authorization: Bearer __KEY__"

--------------------------------------------------------------------------
 2) Claude Desktop  (Settings > Developer > Edit Config)
    claude_desktop_config.json - needs Node.js (uses the mcp-remote bridge)
--------------------------------------------------------------------------
{
  "mcpServers": {
    "myssh": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "__URL__",
               "--header", "Authorization:${MYSSH_AUTH}", "--allow-http"],
      "env": { "MYSSH_AUTH": "Bearer __KEY__" }
    }
  }
}
(drop "--allow-http" once you serve the MCP over https://)

--------------------------------------------------------------------------
 3) OpenAI Codex CLI  (~/.codex/config.toml)
--------------------------------------------------------------------------
[mcp_servers.myssh]
url = "__URL__"
http_headers = { "Authorization" = "Bearer __KEY__" }
# older Codex versions also need, at the top level:  experimental_use_rmcp_client = true

--------------------------------------------------------------------------
 4) Cursor (~/.cursor/mcp.json)
--------------------------------------------------------------------------
{
  "mcpServers": {
    "myssh": {
      "url": "__URL__",
      "headers": { "Authorization": "Bearer __KEY__" }
    }
  }
}

    VS Code (.vscode/mcp.json)
{
  "servers": {
    "myssh": {
      "type": "http",
      "url": "__URL__",
      "headers": { "Authorization": "Bearer __KEY__" }
    }
  }
}

--------------------------------------------------------------------------
 5) Most secure: over SSH (no open port, no API key, encrypted by SSH)
--------------------------------------------------------------------------
Claude Code:
  claude mcp add myssh-ssh -- ssh -T root@__HOST__ /usr/local/bin/myssh-mcp stdio
Claude Desktop / Cursor:
  { "mcpServers": { "myssh": { "command": "ssh",
      "args": ["-T", "root@__HOST__", "/usr/local/bin/myssh-mcp", "stdio"] } } }
(requires key-based SSH login; the same safety policy and audit log apply)

--------------------------------------------------------------------------
 6) Quick test from any machine
--------------------------------------------------------------------------
curl -s __URL__ \
  -H "Authorization: Bearer __KEY__" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

--------------------------------------------------------------------------
 Security notes
--------------------------------------------------------------------------
* Plain HTTP sends the key unencrypted. For use over the internet put HTTPS
  in front (e.g. Caddy: `reverse_proxy 127.0.0.1:__PORT__` and set
  bind = "127.0.0.1" in the config) or use the SSH method (5).
* Setup already ran `ufw allow __PORT__/tcp`. If your VPS provider has its own
  firewall / security group, open TCP __PORT__ there too.
* 10 wrong keys within 10 minutes => that IP is banned for 15 minutes.
* Tools: execute_command, read_file, write_file, list_directory, system_info,
  service_control, docker, database_query, database_backup, database_backups,
  database_restore.
* Every data-changing database_query is preceded by an automatic backup in
  /var/backups/myssh-mcp/db; ask the AI to "revert with database_restore".
"#;

fn key_file_text(key: &str, cfg: &Config) -> String {
    let url = cfg.server.public_url.clone();
    KEY_FILE_TEMPLATE
        .replace("__DATE__", &crate::audit::now_stamp())
        .replace("__KEY__", key)
        .replace("__SERVER__", &hostport_of(&url))
        .replace("__URL__", &url)
        .replace("__HOST__", &host_of(&url))
        .replace("__PORT__", &cfg.server.port.to_string())
        .replace("__LOG__", &cfg.logging.log_file)
}

fn restart_service() -> Result<(), String> {
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", config::SERVICE_NAME])?;
    systemctl(&["restart", config::SERVICE_NAME])?;
    std::thread::sleep(std::time::Duration::from_millis(1500));
    systemctl(&["is-active", "--quiet", config::SERVICE_NAME]).map_err(|_| {
        "the service did not start — check:  journalctl -u myssh-mcp -n 50 --no-pager".to_string()
    })
}

pub fn run_setup(o: SetupOpts) -> Result<(), String> {
    ensure_root_linux()?;
    let mut cfg = Config::load_or_default(&o.config_path)?;
    if let Some(b) = &o.bind {
        cfg.server.bind = b.clone();
    }
    if let Some(p) = o.port {
        cfg.server.port = p;
    }
    cfg.server
        .bind
        .trim_matches(|c: char| c == '[' || c == ']')
        .parse::<std::net::IpAddr>()
        .map_err(|_| format!("invalid --bind address `{}`", cfg.server.bind))?;

    println!("[1/7] Creating directories and audit log");
    private_dir(config::CONFIG_DIR)?;
    let log = cfg.logging.log_file.clone();
    if let Some(dir) = Path::new(&log).parent() {
        private_dir(&dir.to_string_lossy())?;
    }
    touch_private(&log)?;
    private_dir(config::BACKUP_DIR)?;
    private_dir(config::DB_BACKUP_DIR)?;

    println!("[2/7] Installing binary to {}", config::BINARY_PATH);
    install_binary()?;

    println!("[3/7] Preparing API key");
    let existing = if o.new_key {
        None
    } else {
        read_key_file().filter(|k| auth::verify(k, &cfg.server.api_key_sha256))
    };
    let (key, reused) = match existing {
        Some(k) => (k, true),
        None => (auth::generate_api_key()?, false),
    };
    cfg.server.api_key_sha256 = auth::sha256_hex(&key);

    let keep_url = o.public_host.is_none() && cfg.server.public_url.starts_with("https://");
    if !keep_url {
        let host = o.public_host.clone().unwrap_or_else(detect_host);
        let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host };
        cfg.server.public_url = format!("http://{host}:{}/mcp", cfg.server.port);
    }

    println!("[4/7] Writing {}", o.config_path);
    write_with_mode(&o.config_path, &config::render_config(&cfg), 0o600)?;
    write_with_mode(config::API_KEY_FILE, &key_file_text(&key, &cfg), 0o600)?;

    println!("[5/7] Installing systemd service + log rotation");
    write_with_mode(config::UNIT_PATH, &unit_text(&o.config_path), 0o644)?;
    write_with_mode(config::LOGROTATE_PATH, &logrotate_text(&log), 0o644)?;

    println!("[6/7] Opening port {}/tcp in ufw", cfg.server.port);
    let firewall = match open_firewall(cfg.server.port) {
        Ok(msg) => msg,
        Err(e) => format!("WARNING: could not add the ufw rule ({e}) — run:  ufw allow {}/tcp", cfg.server.port),
    };
    println!("      {firewall}");

    if o.no_start {
        println!("[7/7] Skipping service start (--no-start)");
        systemctl(&["daemon-reload"])?;
    } else {
        println!("[7/7] Enabling and starting {}", config::SERVICE_NAME);
        restart_service()?;
    }

    println!();
    println!("==================================================================");
    println!(" MySSH-MCP is installed{}", if o.no_start { "" } else { " and running" });
    println!("==================================================================");
    println!(" Server    : {}", hostport_of(&cfg.server.public_url));
    println!(" MCP URL   : {}", cfg.server.public_url);
    println!(" Firewall  : {firewall}");
    println!(
        " API key   : {} ({})",
        config::API_KEY_FILE,
        if reused { "existing key kept" } else { "NEW key generated" }
    );
    println!(" Audit log : {log}");
    println!(" Config    : {}", o.config_path);
    println!(" Service   : systemctl status {}", config::SERVICE_NAME);
    println!();
    println!(" Connect your AI with the instructions in:");
    println!("   sudo cat {}", config::API_KEY_FILE);
    println!("==================================================================");
    Ok(())
}

pub fn rotate_key(config_path: &str) -> Result<(), String> {
    ensure_root_linux()?;
    let mut cfg = Config::load(config_path)?;
    let key = auth::generate_api_key()?;
    cfg.server.api_key_sha256 = auth::sha256_hex(&key);
    write_with_mode(config_path, &config::render_config(&cfg), 0o600)?;
    write_with_mode(config::API_KEY_FILE, &key_file_text(&key, &cfg), 0o600)?;
    if Path::new(config::UNIT_PATH).exists() {
        systemctl(&["restart", config::SERVICE_NAME])?;
    }
    println!("New API key written to {} — the old key no longer works.", config::API_KEY_FILE);
    println!("Update your AI client configuration:  sudo cat {}", config::API_KEY_FILE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("http://10.50.0.1:4040/mcp"), "10.50.0.1");
        assert_eq!(hostport_of("http://10.50.0.1:4040/mcp"), "10.50.0.1:4040");
        assert_eq!(host_of("https://mcp.example.com/mcp"), "mcp.example.com");
        assert_eq!(host_of("http://[2001:db8::1]:4040/mcp"), "2001:db8::1");
    }

    #[test]
    fn key_file_contains_everything() {
        let mut cfg = Config::default();
        cfg.server.public_url = "http://10.50.0.1:4040/mcp".into();
        let t = key_file_text("msmcp_abc", &cfg);
        assert!(t.contains("SERVER=10.50.0.1:4040"));
        assert!(t.contains("API_KEY=msmcp_abc"));
        assert!(t.contains("MCP_URL=http://10.50.0.1:4040/mcp"));
        assert!(t.contains("ufw allow 4040/tcp"));
        assert!(t.contains("claude mcp add --transport http"));
        assert!(t.contains("root@10.50.0.1"));
        assert!(!t.contains("__"));
    }
}
