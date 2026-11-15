# MySSH-MCP

Let **Claude, Codex or any MCP client** manage your **Ubuntu / Linux VPS as root** with a
safety policy in front of every command and a complete audit log.

- **Rust**: single binary, runs as a **systemd service with root access**, starts on boot.
- **One-command install**: builds, installs, **generates the API key** and writes it with
  copy-paste connection instructions to **`/home/MCP_MySSH_APIKey.txt`**.
- **Blocks dangerous commands** such as `rm -rf ./`, `rm -rf /`, `mkfs`, `dd of=/dev/sda`, fork bombs,
  `chmod -R 777 /`, stopping SSH, firewall flushes, `curl | bash`, `DROP DATABASE`, `docker volume rm`, ...
- **Logs everything** (granted, denied, results, failed logins) with an exact timestamp to
  **`/server_log/claude_log.txt`**.
- **Docker, databases (MySQL/MariaDB, PostgreSQL, SQLite) and systemd services** are available as tools.

> Linux only (tested target: Ubuntu 20.04+ / Debian 11+ with systemd).

---

## Install

```bash
git clone <this-repo-url> MySSH-MCP
cd MySSH-MCP
sudo ./install.sh
sudo cat /home/MCP_MySSH_APIKey.txt      # API key + how to connect
```

The installer installs the build tools and Rust (rustup) when needed, compiles a release build,
adds a temporary swap file on small VPS (under 2 GB RAM), then runs `myssh-mcp setup`, which:

1. creates `/server_log/claude_log.txt` (mode 600) and `/etc/myssh-mcp/config.toml`
2. installs `/usr/local/bin/myssh-mcp`
3. **generates a 256-bit API key**. Only its SHA-256 goes into the config. The plain key goes to
   `/home/MCP_MySSH_APIKey.txt` (mode 600) together with connection instructions for every client.
4. installs and starts the `myssh-mcp` systemd service (`User=root`, `Restart=always`, enabled at boot)
5. installs log rotation (`/etc/logrotate.d/myssh-mcp`)

Re-running `./install.sh` upgrades in place and **keeps the existing key**.

| Option | Meaning |
|---|---|
| `--port 8765` | listen port |
| `--bind 0.0.0.0` | listen address (`127.0.0.1` behind a reverse proxy / SSH tunnel) |
| `--public-host my.vps.com` | host/IP written into the connection guide (auto-detected otherwise) |
| `--new-key` | force a new API key |
| `--open-firewall` | `ufw allow <port>/tcp` if ufw is active |

## Connect your AI

`/home/MCP_MySSH_APIKey.txt` contains ready-to-paste snippets for Claude Code, Claude Desktop,
Codex CLI, Cursor, VS Code and a `curl` test. For example, Claude Code:

```bash
claude mcp add --transport http --scope user myssh http://YOUR_VPS_IP:8765/mcp \
  --header "Authorization: Bearer msmcp_xxxxxxxx..."
```

**Most secure option: over SSH** (no open port, no API key, encrypted by SSH; same policy and log):

```bash
claude mcp add myssh-ssh -- ssh -T root@YOUR_VPS_IP /usr/local/bin/myssh-mcp stdio
```

## Tools

| Tool | What it does |
|---|---|
| `execute_command` | `bash -c` as root (non-interactive, timeout, output cap), policy-checked |
| `read_file` | read text files (`tail_lines` for big logs) |
| `write_file` | create/overwrite/append; existing files are **backed up** to `/var/backups/myssh-mcp` first |
| `list_directory` | `ls -la`-style listing |
| `system_info` | OS, kernel, uptime, load, RAM, disks, listening ports, Docker containers, failed units |
| `service_control` | `systemctl status/start/stop/restart/reload/enable/disable`, journal logs |
| `docker` | docker CLI with an argument array (no shell), including `docker compose` |
| `database_query` | SQL via `mysql`/`mariadb`, `psql` (peer auth as `postgres`) or `sqlite3` |

## What gets blocked

Every command is parsed (pipes, `&&`, `;`, `$(...)`, backticks, `bash -c`, `sudo`, `su -c`, `env`,
`xargs`, `find -exec`, heredocs, `$'\x..'` escapes, brace expansion, symlinks, scripts it is asked
to run...) and checked by per-program rules. A raw-text scan also catches dangerous strings hidden
inside `python -c`, `perl -e` and similar.

| Category | Examples that are **DENIED** |
|---|---|
| Mass deletion | `rm -rf /`, `rm -rf ./`, `rm -rf *`, `rm -rf ~`, `rm -rf /etc`, `rm -rf $VAR/`, `find / -delete`, `xargs rm -rf`, `rsync --delete ... /var/` |
| Disks | `mkfs.*`, `dd of=/dev/sda`, `> /dev/sda`, `wipefs -a`, `fdisk`/`parted` (write mode), `blkdiscard` |
| System killers | fork bombs, `chmod -R 777 /`, `chown -R` on system dirs, `kill -9 1`, `kill -9 -1`, `killall5`, `echo b > /proc/sysrq-trigger` |
| Power | `reboot`, `shutdown`, `poweroff`, `init 0/6`, `systemctl poweroff` (configurable) |
| Lock-out | stopping/disabling `ssh`, `iptables -F`, `iptables -P INPUT DROP`, `ufw deny 22`, `ufw reset`, `ip link set eth0 down`, deleting the default route, editing `/etc/passwd`, `/etc/shadow`, sudoers, `sshd_config`, `authorized_keys`, `passwd -l root`, `userdel root` |
| Packages | removing `openssh-server`, `systemd`, `libc6`, `sudo`, `apt`, the running kernel, ...; wildcard removals |
| Evasion | `curl … \| bash`, `bash <(curl …)`, `base64 -d \| sh`, `eval "$(… base64 -d)"`, `$(echo rm) -rf`, `$CMD …` |
| Docker | `system prune`, `volume rm/prune`, `container prune`, `compose down -v`, `--privileged`, `-v /:/host` |
| Databases | `DROP DATABASE/TABLE`, `TRUNCATE`, `DELETE`/`UPDATE` without `WHERE`, `COPY … PROGRAM`, `INTO OUTFILE`, `\!` shell escapes, `FLUSHALL`, `dropdb` |
| Self-protection | anything that modifies MySSH-MCP's config, audit log, binary, service, backups, or reads the API key file |

Normal admin work stays allowed: `apt install`, `systemctl restart nginx`, `rm -rf ./build`,
`docker compose up -d`, `chown -R www-data /var/www/html`, `find /var/log -name '*.gz' -mtime +30 -delete`,
`SELECT ... / UPDATE ... WHERE ...`, editing configs under `/etc/nginx`, and so on.

When a call is denied, the AI gets a clear `⛔ DENIED` message with the reason and is told not to
work around it.

Test any command yourself:

```bash
sudo myssh-mcp check "rm -rf ./"                 # DENIED: recursive delete of /, ., .., * or ~ is blocked
sudo myssh-mcp check "systemctl restart nginx"   # ALLOWED
sudo myssh-mcp check-sql "DELETE FROM users"     # DENIED: DELETE without WHERE ...
```

## Audit log: `/server_log/claude_log.txt`

One line per event with an exact local timestamp, the client IP and the full command:

```text
[2026-11-15 14:03:21.004 +08:00] [SYSTEM ] client=- msg="MySSH-MCP v1.0.0 listening on http://0.0.0.0:8765/mcp (audit log: /server_log/claude_log.txt)"
[2026-11-15 14:03:22.123 +08:00] [GRANTED] client=203.0.113.7 tool=execute_command cmd="apt-get install -y nginx" cwd="/root" timeout=120s
[2026-11-15 14:03:41.870 +08:00] [RESULT ] client=203.0.113.7 tool=execute_command exit=0 signal=- duration_ms=19745 timed_out=false truncated=false stdout_bytes=5120 stderr_bytes=0
[2026-11-15 14:04:02.511 +08:00] [DENIED ] client=203.0.113.7 tool=execute_command cmd="rm -rf ./" cwd="/root" reason="recursive delete of /, ., .., * or ~ is blocked"
[2026-11-15 14:05:10.002 +08:00] [AUTHFAIL] client=198.51.100.4 reason="invalid API key" user_agent="curl/8.5.0"
```

Watch it live: `sudo tail -f /server_log/claude_log.txt`. The log is rotated weekly (12 weeks kept).

## Configuration: `/etc/myssh-mcp/config.toml`

Fully commented. You can change the port and bind address, timeouts and output limits, and the
`allow_reboot`, `allow_remote_script_pipe`, `allow_destructive_sql` and
`allow_privileged_containers` switches. You can also edit the lists of protected directories,
files, services and packages, and add your own `extra_deny_patterns` (regex). Apply changes with
`sudo systemctl restart myssh-mcp`.

Some protections cannot be switched off: self-protection, fork bombs, disk formatting, and
recursive deletes of `/`, `.`, `..`, `*`, `~` and top-level directories.

## CLI

```text
myssh-mcp serve                 run the HTTP MCP server (what the service runs)
myssh-mcp stdio                 MCP over stdin/stdout (for ssh)
myssh-mcp setup [options]       install/update key, config, service (root)
myssh-mcp rotate-key            new API key, old one stops working (root)
myssh-mcp check "<command>"     test a command against the policy
myssh-mcp check-sql "<sql>"     test a query against the policy
```

## Security notes and limits

- **This is a guard rail, not a sandbox.** It stops accidents, hallucinated commands and
  prompt-injected AIs from wrecking the server. It cannot stop a determined human with root.
  Anything the policy does not block runs as root.
- **Plain HTTP sends the API key unencrypted.** On the open internet, use the SSH transport or put
  HTTPS in front (e.g. Caddy `reverse_proxy 127.0.0.1:8765` with `bind = "127.0.0.1"`). Open the port
  only to the IPs you need.
- 10 failed API keys in 10 minutes ban the IP for 15 minutes (logged as `AUTHFAIL`).
- The AI cannot read the key file or change MySSH-MCP's own files, service or log. For tamper-proof
  records, also ship the log off the server (rsyslog, Loki, ...).
- Rotate the key whenever it may have leaked: `sudo myssh-mcp rotate-key`.

## Uninstall

```bash
sudo ./uninstall.sh            # remove service and binary (keeps config, key, logs)
sudo ./uninstall.sh --purge    # also delete config, key file and backups (log is kept)
```

## Development

```bash
cargo test          # policy, parser, auth and config tests
cargo build --release
```

```text
src/
  main.rs        CLI (serve, stdio, setup, rotate-key, check, check-sql)
  http.rs        MCP Streamable HTTP transport + API-key auth + brute-force ban
  stdio.rs       MCP over stdin/stdout
  mcp.rs         JSON-RPC / MCP protocol (initialize, tools/list, tools/call, ...)
  tools/         execute_command, files, system, docker, database tools
  policy/        safety policy: shell parser, path rules, program rules, SQL rules, tests
  exec.rs        process runner (timeouts, process-group kill, output caps)
  audit.rs       audit log
  setup.rs       installer logic, systemd unit, key file + connection guide
  config.rs      config file
```
