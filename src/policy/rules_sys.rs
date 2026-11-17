//! Program rules: power, services, processes, users, cron, firewall, network, packages,
//! docker, database CLIs, mounts and disk tools.

use super::paths::*;
use super::rules_fs::{opt_value, split_args};
use super::{Ctx, Policy, Verdict, SELF_MSG};
use crate::config;

const SELF_SAFE_ACTIONS: &[&str] = &[
    "status", "show", "is-active", "is-enabled", "is-failed", "cat", "list-dependencies", "help",
    "list-units", "list-unit-files",
];

fn is_virtual_iface(d: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "dummy", "cni", "flannel", "cali",
        "vxlan", "lxc", "lxd", "tailscale", "zt",
    ];
    PREFIXES.iter().any(|p| d.starts_with(p))
}

fn has_any(args: &[String], list: &[&str]) -> bool {
    args.iter().any(|a| list.contains(&a.as_str()))
}

fn is_disk_tool(p: &str) -> bool {
    p.starts_with("mkfs")
        || matches!(
            p,
            "mke2fs" | "mkdosfs" | "mkntfs" | "mkswap" | "wipefs" | "blkdiscard" | "fdisk" | "sfdisk"
                | "cfdisk" | "gdisk" | "sgdisk" | "cgdisk" | "parted" | "pvremove" | "vgremove"
                | "lvremove" | "lvreduce" | "zpool" | "zfs" | "cryptsetup" | "badblocks" | "hdparm"
                | "nvme"
        )
}

impl Policy {
    pub(crate) fn check_program_sys(&self, c: &Ctx) -> Verdict {
        match c.prog {
            "shutdown" | "reboot" | "poweroff" | "halt" | "kexec" | "init" | "telinit" => self.rule_power(c),
            "systemctl" => self.rule_systemctl(c),
            "service" => self.rule_service(c),
            "kill" => self.rule_kill(c),
            "pkill" | "killall" => self.rule_pkill(c),
            "killall5" => Err("`killall5` kills every process on the server".into()),
            "userdel" | "deluser" | "passwd" | "usermod" => self.rule_users(c),
            "crontab" => {
                let a = split_args(c.args, &["-u"]);
                if a.short('r') || a.long("--remove") {
                    Err("`crontab -r` deletes every cron job — use `crontab -l > file`, edit, then `crontab file`".into())
                } else {
                    Ok(())
                }
            }
            "iptables" | "ip6tables" | "iptables-legacy" | "iptables-nft" | "ip6tables-legacy"
            | "ip6tables-nft" => self.rule_iptables(c),
            "nft" => {
                let j = c.args.join(" ").to_lowercase();
                if j.contains("flush ruleset") {
                    Err("`nft flush ruleset` wipes the whole firewall (lock-out risk, breaks Docker networking)".into())
                } else {
                    Ok(())
                }
            }
            "ufw" => self.rule_ufw(c),
            "ip" => self.rule_ip(c),
            "ifdown" => {
                let a = split_args(c.args, &["-i", "--interfaces", "--state-dir"]);
                if a.short('a') || a.long("--all") {
                    return Err("`ifdown -a` takes every network interface offline".into());
                }
                for d in &a.pos {
                    if !is_virtual_iface(d) {
                        return Err(format!("`ifdown {d}` would take a network interface offline (lock-out)"));
                    }
                }
                Ok(())
            }
            "ifconfig" => {
                let a = split_args(c.args, &[]);
                if a.pos.contains(&"down") {
                    let dev = a.pos.first().copied().unwrap_or("");
                    if !is_virtual_iface(dev) {
                        return Err(format!("`ifconfig {dev} down` would take a network interface offline (lock-out)"));
                    }
                }
                Ok(())
            }
            "nmcli" => {
                let j = c.args.join(" ").to_lowercase();
                if j.contains("networking off") || j.contains("radio all off") {
                    Err("disabling NetworkManager networking would cut the server off".into())
                } else {
                    Ok(())
                }
            }
            "apt" | "apt-get" | "aptitude" => self.rule_apt(c),
            "dpkg" => self.rule_dpkg(c),
            "docker" | "podman" => self.rule_docker(c),
            "docker-compose" | "podman-compose" => self.rule_compose(c.args),
            "mysql" | "mariadb" | "psql" | "sqlite3" | "mysqladmin" | "mariadb-admin" | "dropdb"
            | "redis-cli" => self.rule_db_cli(c),
            "mount" | "umount" => self.rule_mount(c),
            p if is_disk_tool(p) => self.rule_disk(c),
            _ => Ok(()),
        }
    }

    fn rule_power(&self, c: &Ctx) -> Verdict {
        let p = c.prog;
        if p == "init" || p == "telinit" {
            let lvl = c.args.iter().map(|s| s.as_str()).find(|a| !a.starts_with('-'));
            return match lvl {
                Some("0") | Some("6") if !self.allow_reboot => {
                    Err(format!("`{p} {}` would power off / reboot the server (allow_reboot = false)", lvl.unwrap_or("")))
                }
                Some("1") | Some("s") | Some("S") | Some("single") | Some("emergency") => {
                    Err(format!("`{p}` to single-user/rescue mode would cut network access"))
                }
                _ => Ok(()),
            };
        }
        if p == "shutdown" && c.args.iter().any(|a| a == "-c" || a == "--cancel") {
            return Ok(());
        }
        if self.allow_reboot {
            return Ok(());
        }
        Err(format!("`{p}` would shut down / reboot the server — blocked (set allow_reboot = true to permit)"))
    }

    fn rule_systemctl(&self, c: &Ctx) -> Verdict {
        let a = split_args(
            c.args,
            &[
                "-t", "--type", "-s", "--signal", "-H", "--host", "-M", "--machine", "-p", "--property",
                "--state", "-n", "--lines", "-o", "--output", "--root", "--kill-whom", "--kill-value",
                "--what", "--timestamp", "--message", "--job-mode", "--when",
            ],
        );
        let Some(&action) = a.pos.first() else { return Ok(()) };
        let units = &a.pos[1..];
        match action {
            "poweroff" | "reboot" | "halt" | "kexec" | "soft-reboot" | "suspend" | "hibernate"
            | "hybrid-sleep" | "suspend-then-hibernate" => {
                if !self.allow_reboot {
                    return Err(format!("`systemctl {action}` would take the server down — blocked (allow_reboot = false)"));
                }
            }
            "rescue" | "emergency" | "isolate" | "default" => {
                return Err(format!("`systemctl {action}` switches the system target and can cut network/SSH access"));
            }
            "set-default" => {
                if units.iter().any(|u| !matches!(*u, "multi-user.target" | "graphical.target")) {
                    return Err("`systemctl set-default` to a non-standard target is blocked".into());
                }
            }
            _ => {}
        }
        let stopping = matches!(action, "stop" | "disable" | "mask" | "kill" | "freeze");
        for u in units {
            let base = u.trim_end_matches(".service");
            if base == config::SERVICE_NAME && !SELF_SAFE_ACTIONS.contains(&action) {
                return Err(format!("`systemctl {action} {u}`: MySSH-MCP cannot stop/restart/modify its own service"));
            }
            if stopping {
                if has_glob(u) {
                    return Err(format!("`systemctl {action} {u}` with a wildcard unit is blocked"));
                }
                if self.protected_services.iter().any(|s| s == u || s == base) {
                    return Err(format!(
                        "`systemctl {action} {u}` would stop a protected service (SSH/network/logging) and could lock you out"
                    ));
                }
            }
        }
        Ok(())
    }

    fn rule_service(&self, c: &Ctx) -> Verdict {
        let pos: Vec<&str> = c.args.iter().map(|s| s.as_str()).filter(|a| !a.starts_with('-')).collect();
        if pos.len() < 2 {
            return Ok(());
        }
        let (name, action) = (pos[0], pos[1]);
        if name == config::SERVICE_NAME && action != "status" {
            return Err(format!("`service {name} {action}`: MySSH-MCP cannot stop/restart its own service"));
        }
        if matches!(action, "stop" | "force-stop") && self.protected_services.iter().any(|s| s == name) {
            return Err(format!("`service {name} {action}` would stop a protected service and could lock you out"));
        }
        Ok(())
    }

    fn rule_kill(&self, c: &Ctx) -> Verdict {
        let args = c.args;
        let mut targets: Vec<&str> = Vec::new();
        let mut seen_signal = false;
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if matches!(a, "-l" | "-L" | "--list" | "--table") {
                return Ok(());
            }
            if matches!(a, "-s" | "-n" | "--signal") {
                seen_signal = true;
                i += 2;
                continue;
            }
            if a == "--" {
                targets.extend(args[i + 1..].iter().map(|s| s.as_str()));
                break;
            }
            if !seen_signal && targets.is_empty() && a.starts_with('-') && a.len() > 1 {
                seen_signal = true;
                i += 1;
                continue;
            }
            targets.push(a);
            i += 1;
        }
        for t in targets {
            if t == "1" || t == "-1" || t == self.own_pid {
                return Err(format!("`kill {t}` would kill init / every process / MySSH-MCP itself"));
            }
            if has_dynamic(t) {
                let l = t.to_lowercase();
                if let Some(p) = self.protected_procs.iter().find(|p| l.contains(p.as_str())) {
                    return Err(format!("`kill {t}` targets protected process `{p}`"));
                }
            }
        }
        Ok(())
    }

    fn rule_pkill(&self, c: &Ctx) -> Verdict {
        let a = split_args(
            c.args,
            &[
                "-u", "-U", "-g", "-G", "-P", "-s", "-t", "-F", "--signal", "--euid", "--uid", "--pgroup",
                "--group", "--parent", "--session", "--terminal", "--pidfile", "--ns", "--nslist",
                "--user", "-o", "--older-than", "-y", "--younger-than",
            ],
        );
        if let Some(u) = opt_value(c.args, &["-u", "-U", "--uid", "--euid", "--user"]) {
            if u.split(',').any(|x| x == "root" || x == "0") {
                return Err(format!("`{} -u root` would kill every root process including sshd", c.prog));
            }
        }
        for pat in &a.pos {
            let p = pat.trim_matches(|ch: char| ch == '^' || ch == '$').to_lowercase();
            if p.is_empty() || p == "." || p == ".*" || p == ".+" {
                return Err(format!("`{} {pat}` matches every process", c.prog));
            }
            for prot in &self.protected_procs {
                if prot.contains(p.as_str()) || p.contains(prot.as_str()) {
                    return Err(format!("`{} {pat}` would kill protected process `{prot}`", c.prog));
                }
            }
        }
        Ok(())
    }

    fn rule_users(&self, c: &Ctx) -> Verdict {
        let p = c.prog;
        let value_opts: &[&str] = match p {
            "usermod" => &[
                "-c", "-d", "-e", "-f", "-g", "-G", "-l", "-p", "-s", "-u", "-R", "-P", "-Z", "--comment",
                "--home", "--expiredate", "--inactive", "--gid", "--groups", "--login", "--password",
                "--shell", "--uid", "--root", "--prefix",
            ],
            "passwd" => &[
                "-n", "-x", "-w", "-i", "-r", "-R", "-P", "--mindays", "--maxdays", "--warndays",
                "--inactive", "--repository", "--root", "--prefix",
            ],
            _ => &["-R", "--root", "-P", "--prefix"],
        };
        let a = split_args(c.args, value_opts);
        let default_user = if p == "passwd" { "root" } else { "" };
        let user = a.pos.last().copied().unwrap_or(default_user);
        if user != "root" {
            return Ok(());
        }
        match p {
            "userdel" | "deluser" => Err("deleting the root account is blocked".into()),
            "passwd" => {
                if a.short('l') || a.short('d') || a.short('e') || a.long("--lock") || a.long("--delete") || a.long("--expire") {
                    Err("locking / deleting / expiring the root password is blocked (lock-out protection)".into())
                } else {
                    Ok(())
                }
            }
            "usermod" => {
                let shell = opt_value(c.args, &["-s", "--shell"]).unwrap_or("");
                let bad = a.short('L')
                    || a.long("--lock")
                    || a.short('e')
                    || a.long("--expiredate")
                    || a.short('l')
                    || a.long("--login")
                    || a.short('u')
                    || a.long("--uid")
                    || shell.contains("nologin")
                    || shell.ends_with("false");
                if bad {
                    Err("locking / renaming / disabling the root account is blocked (lock-out protection)".into())
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn rule_iptables(&self, c: &Ctx) -> Verdict {
        let args: Vec<&str> = c.args.iter().map(|s| s.as_str()).collect();
        let builtin = |ch: &str| {
            matches!(ch, "INPUT" | "OUTPUT" | "FORWARD" | "PREROUTING" | "POSTROUTING") || ch.starts_with("DOCKER")
        };
        for (i, a) in args.iter().enumerate() {
            let next = args.get(i + 1).copied();
            match *a {
                "-F" | "--flush" | "-X" | "--delete-chain" => match next.filter(|n| !n.starts_with('-')) {
                    None => {
                        return Err(format!(
                            "`{} {a}` without a chain flushes/deletes ALL firewall rules (lock-out risk, breaks Docker networking)",
                            c.prog
                        ))
                    }
                    Some(ch) if builtin(ch) => {
                        return Err(format!("`{} {a} {ch}` flushes a built-in/Docker chain (lock-out risk)", c.prog))
                    }
                    _ => {}
                },
                "-P" | "--policy" => {
                    let ch = next.unwrap_or("");
                    let target = args.get(i + 2).copied().unwrap_or("");
                    if matches!(ch, "INPUT" | "OUTPUT") && matches!(target, "DROP" | "REJECT") {
                        return Err(format!("`{} -P {ch} {target}` sets a default-deny policy and would lock you out", c.prog));
                    }
                }
                _ => {}
            }
        }
        let appends_input =
            args.windows(2).any(|w| matches!(w[0], "-A" | "--append" | "-I" | "--insert") && w[1] == "INPUT");
        let drops = args.windows(2).any(|w| matches!(w[0], "-j" | "--jump") && matches!(w[1], "DROP" | "REJECT"));
        if appends_input && drops {
            let filtered = args
                .iter()
                .any(|a| matches!(*a, "-s" | "--source" | "-i" | "--in-interface" | "--ctstate" | "--state"));
            let dport = opt_value(c.args, &["--dport", "--destination-port", "--dports"]);
            let port = self.mcp_port.to_string();
            let hits_access = dport
                .map(|d| d.split(|ch: char| ch == ',' || ch == ':').any(|p| p == "22" || p == "ssh" || p == port))
                .unwrap_or(false);
            if !filtered && (dport.is_none() || hits_access) {
                return Err(format!(
                    "`{}` blanket DROP/REJECT on INPUT would lock you out of SSH / MySSH-MCP",
                    c.prog
                ));
            }
        }
        Ok(())
    }

    fn rule_ufw(&self, c: &Ctx) -> Verdict {
        let pos: Vec<String> = c.args.iter().filter(|a| !a.starts_with("--")).map(|s| s.to_lowercase()).collect();
        let Some(first) = pos.first() else { return Ok(()) };
        let port = self.mcp_port.to_string();
        let mentions_access = pos.iter().any(|a| {
            let p = a.split('/').next().unwrap_or("");
            p == "22" || p == "ssh" || p == "openssh" || p == port
        });
        let from_specific = pos.windows(2).any(|w| w[0] == "from" && w[1] != "any");
        let has = |s: &str| pos.iter().any(|a| a == s);
        match first.as_str() {
            "reset" => Err("`ufw reset` wipes all firewall rules and may drop SSH access".into()),
            "deny" | "reject" | "insert" | "prepend"
                if (has("deny") || has("reject")) && mentions_access && !from_specific =>
            {
                Err("blocking the SSH / MySSH-MCP port with ufw would lock you out".into())
            }
            "delete" if has("allow") && mentions_access => {
                Err("deleting the ufw rule that allows SSH / MySSH-MCP would lock you out".into())
            }
            "default" if (has("deny") || has("reject")) && has("outgoing") => {
                Err("`ufw default deny outgoing` breaks apt, DNS and Docker pulls".into())
            }
            _ => Ok(()),
        }
    }

    fn rule_ip(&self, c: &Ctx) -> Verdict {
        let pos: Vec<&str> = c.args.iter().map(|s| s.as_str()).filter(|a| !a.starts_with('-')).collect();
        let Some(&obj) = pos.first() else { return Ok(()) };
        let after = |kw: &str| pos.windows(2).find(|w| w[0] == kw).map(|w| w[1]);
        let has = |kw: &str| pos.contains(&kw);
        let is_link = "link".starts_with(obj);
        let is_addr = "address".starts_with(obj);
        let is_route = "route".starts_with(obj);
        if is_link && has("set") && has("down") {
            let dev = after("dev").or_else(|| after("set")).unwrap_or("");
            if !is_virtual_iface(dev) {
                return Err(format!("`ip link set {dev} down` would take a network interface offline (lock-out)"));
            }
        }
        if is_addr && (has("flush") || has("del") || has("delete")) {
            let dev = after("dev").or_else(|| after("flush")).unwrap_or("");
            if !is_virtual_iface(dev) && dev != "lo" {
                return Err("removing/flushing IP addresses on a physical interface can cut connectivity".into());
            }
        }
        if is_route && (has("flush") || ((has("del") || has("delete")) && has("default"))) {
            return Err("flushing routes / deleting the default route cuts connectivity".into());
        }
        Ok(())
    }

    fn check_pkg_removal(&self, raw: &str) -> Verdict {
        if raw.chars().any(|ch| matches!(ch, '*' | '?' | '[' | '^' | '~' | '$')) {
            return Err(format!("package removal by pattern `{raw}` is blocked — name packages explicitly"));
        }
        let name = raw.split(|ch: char| ch == ':' || ch == '=' || ch == '/').next().unwrap_or(raw);
        if self.critical_packages.iter().any(|c| c == name) {
            return Err(format!("removing critical package `{name}` would break the OS / remote access"));
        }
        if !self.kernel.is_empty() {
            for prefix in ["linux-image-", "linux-modules-", "linux-headers-"] {
                if name == format!("{prefix}{}", self.kernel) {
                    return Err(format!("removing the running kernel package `{name}` is blocked"));
                }
            }
        }
        Ok(())
    }

    fn rule_apt(&self, c: &Ctx) -> Verdict {
        if c.args.iter().any(|a| a.contains("remove-essential")) {
            return Err("removing essential packages is blocked".into());
        }
        let a = split_args(c.args, &["-o", "-c", "-t", "--option", "--config-file", "--target-release"]);
        let Some(&action) = a.pos.first() else { return Ok(()) };
        let pkgs: Vec<&str> = match action {
            "remove" | "purge" | "autoremove" | "autopurge" | "erase" => a.pos[1..].to_vec(),
            // `apt install foo-` removes foo
            "install" | "reinstall" => a.pos[1..]
                .iter()
                .filter(|p| p.len() > 1 && p.ends_with('-'))
                .map(|p| p.trim_end_matches('-'))
                .collect(),
            _ => Vec::new(),
        };
        for p in pkgs {
            self.check_pkg_removal(p)?;
        }
        Ok(())
    }

    fn rule_dpkg(&self, c: &Ctx) -> Verdict {
        if c.args.iter().any(|a| a.contains("remove-essential") || a == "--force-all" || a.contains("force-depends")) {
            return Err("forcing dpkg past essential/dependency checks is blocked".into());
        }
        let removing = c.args.iter().any(|a| matches!(a.as_str(), "-r" | "-P" | "--remove" | "--purge"));
        if !removing {
            return Ok(());
        }
        for p in c.args.iter().filter(|a| !a.starts_with('-')) {
            self.check_pkg_removal(p)?;
        }
        Ok(())
    }

    fn rule_docker(&self, c: &Ctx) -> Verdict {
        let args = c.args;
        let mut i = 0;
        while i < args.len() && args[i].starts_with('-') {
            let global_with_value = matches!(
                args[i].as_str(),
                "-H" | "--host" | "--context" | "-c" | "--config" | "-l" | "--log-level" | "--tlscacert" | "--tlscert" | "--tlskey"
            );
            i += if global_with_value { 2 } else { 1 };
        }
        let Some(sub) = args.get(i).map(|s| s.as_str()) else { return Ok(()) };
        let rest = &args[i + 1..];
        let first_pos = rest.iter().find(|a| !a.starts_with('-')).map(|s| s.as_str());
        match (sub, first_pos) {
            ("system", Some("prune")) => Err(
                "`docker system prune` deletes stopped containers, networks and possibly images/volumes — blocked; remove specific objects instead".into(),
            ),
            ("volume", Some("rm" | "remove" | "prune")) => {
                Err("deleting Docker volumes destroys persistent data (databases, uploads) — blocked".into())
            }
            ("container", Some("prune")) => Err("`docker container prune` deletes every stopped container — blocked".into()),
            ("container", Some("run" | "create")) => {
                let idx = rest.iter().position(|a| a == "run" || a == "create").unwrap_or(0);
                self.rule_container_create(&rest[idx + 1..])
            }
            ("compose", _) => self.rule_compose(rest),
            ("run" | "create", _) => self.rule_container_create(rest),
            ("exec", _) => self.rule_docker_exec(rest, c),
            _ => Ok(()),
        }
    }

    /// `docker exec [opts] CONTAINER mysql -e "..."`: apply the database client rules inside containers.
    fn rule_docker_exec(&self, rest: &[String], c: &Ctx) -> Verdict {
        const VALUE: &[&str] = &["-u", "--user", "-e", "--env", "-w", "--workdir", "--env-file", "--detach-keys"];
        let mut i = 0;
        while i < rest.len() && rest[i].starts_with('-') {
            i += if VALUE.contains(&rest[i].as_str()) { 2 } else { 1 };
        }
        let Some(exe) = rest.get(i + 1) else { return Ok(()) };
        let prog = basename(exe);
        if matches!(
            prog,
            "mysql" | "mariadb" | "psql" | "sqlite3" | "mysqladmin" | "mariadb-admin" | "dropdb" | "redis-cli"
        ) {
            let inner = Ctx { prog, exe, args: &rest[i + 2..], cwd: c.cwd, via_xargs: false, depth: c.depth };
            return self.rule_db_cli(&inner);
        }
        Ok(())
    }

    fn rule_compose(&self, args: &[String]) -> Verdict {
        let down = args.iter().any(|a| a == "down");
        let volumes = args.iter().any(|a| a == "-v" || a == "--volumes" || a == "--volumes=true");
        if down && volumes {
            return Err("`docker compose down -v` deletes the project's volumes (persistent data) — run `down` without -v".into());
        }
        Ok(())
    }

    fn rule_container_create(&self, args: &[String]) -> Verdict {
        for (i, a) in args.iter().enumerate() {
            let a = a.as_str();
            if a.starts_with("--privileged") && a != "--privileged=false" && !self.allow_privileged_containers {
                return Err("`--privileged` containers can take over the host — blocked (allow_privileged_containers = false)".into());
            }
            let vol = if a == "-v" || a == "--volume" {
                args.get(i + 1).map(|s| s.as_str())
            } else if let Some(v) = a.strip_prefix("--volume=") {
                Some(v)
            } else if a.starts_with("-v") && !a.starts_with("--") && a.len() > 2 {
                Some(&a[2..])
            } else {
                None
            };
            if let Some(v) = vol {
                let mut parts = v.split(':');
                let src = parts.next().unwrap_or("");
                let ro = parts.nth(1).map(|o| o.split(',').any(|x| x == "ro" || x == "readonly")).unwrap_or(false);
                self.check_bind(src, ro)?;
            }
            let mnt = if a == "--mount" { args.get(i + 1).map(|s| s.as_str()) } else { a.strip_prefix("--mount=") };
            if let Some(m) = mnt {
                let (mut src, mut ro, mut bind) = ("", false, false);
                for kv in m.split(',') {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    match k {
                        "type" => bind = v == "bind",
                        "source" | "src" => src = v,
                        "readonly" | "ro" => ro = v.is_empty() || v == "true" || v == "1",
                        _ => {}
                    }
                }
                if bind {
                    self.check_bind(src, ro)?;
                }
            }
        }
        Ok(())
    }

    fn check_bind(&self, src: &str, ro: bool) -> Verdict {
        if !src.starts_with('/') {
            return Ok(()); // named volume
        }
        let Some(n) = normalize(src, Some("/")) else { return Ok(()) };
        if n == "/" {
            return Err("bind-mounting the host root filesystem into a container is blocked".into());
        }
        if self.self_touch(&n) {
            return Err(format!("bind-mounting `{n}`: {SELF_MSG}"));
        }
        let system = CORE_SYSTEM_DIRS.iter().any(|d| *d == n && *d != "/tmp" && *d != "/home");
        if !ro && (self.self_destroy(&n) || system) {
            return Err(format!("read-write bind mount of system directory `{n}` is blocked — add `:ro`"));
        }
        Ok(())
    }

    fn rule_db_cli(&self, c: &Ctx) -> Verdict {
        let pos: Vec<&str> = c.args.iter().map(|s| s.as_str()).filter(|a| !a.starts_with('-')).collect();
        let lower: Vec<String> = pos.iter().map(|s| s.to_lowercase()).collect();
        let has = |s: &str| lower.iter().any(|a| a == s);
        match c.prog {
            "mysql" | "mariadb" => {
                let inline = opt_value(c.args, &["-e", "--execute"]).map(String::from).or_else(|| {
                    c.args.iter().find_map(|a| a.strip_prefix("-e").filter(|r| !r.is_empty()).map(String::from))
                });
                match inline {
                    Some(sql) => self.check_sql(&sql),
                    None => Ok(()),
                }
            }
            "psql" => match opt_value(c.args, &["-c", "--command"]) {
                Some(sql) => self.check_sql(sql),
                None => Ok(()),
            },
            "sqlite3" => {
                if let Some(cmd) = opt_value(c.args, &["-cmd"]) {
                    self.check_sql(cmd)?;
                }
                match pos.get(1) {
                    Some(sql) => self.check_sql(sql),
                    None => Ok(()),
                }
            }
            "mysqladmin" | "mariadb-admin" => {
                if has("shutdown") {
                    Err("`mysqladmin shutdown` stops the database server".into())
                } else if has("drop") && !self.allow_destructive_sql {
                    Err("`mysqladmin drop` deletes a database — blocked (allow_destructive_sql = false)".into())
                } else {
                    Ok(())
                }
            }
            "dropdb" if !self.allow_destructive_sql => {
                Err("`dropdb` deletes a database — blocked (allow_destructive_sql = false)".into())
            }
            "redis-cli" => {
                if has("shutdown") {
                    Err("`redis-cli shutdown` stops Redis".into())
                } else if (has("flushall") || has("flushdb")) && !self.allow_destructive_sql {
                    Err("FLUSHALL / FLUSHDB wipes Redis — blocked (allow_destructive_sql = false)".into())
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn rule_mount(&self, c: &Ctx) -> Verdict {
        let a = split_args(c.args, &["-t", "-o", "-O", "--types", "--options", "-L", "-U", "--label", "--uuid"]);
        if c.prog == "umount" {
            if a.short('a') || a.long("--all") {
                return Err("`umount -a` unmounts every filesystem".into());
            }
            for t in &a.pos {
                if let Some(n) = normalize(t, c.cwd) {
                    if CORE_SYSTEM_DIRS.contains(&n.as_str()) || n == "/boot/efi" {
                        return Err(format!("unmounting `{n}` would break the running system"));
                    }
                }
            }
            return Ok(());
        }
        let opts = opt_value(c.args, &["-o", "--options"]).unwrap_or("");
        if opts.contains("remount") && opts.split(',').any(|o| o == "ro") {
            return Err("remounting a filesystem read-only can freeze the server".into());
        }
        Ok(())
    }

    fn rule_disk(&self, c: &Ctx) -> Verdict {
        let p = c.prog;
        let has = |s: &str| c.args.iter().any(|a| a == s);
        let blocked = || -> Verdict {
            Err(format!("`{p}` can destroy disks/partitions/filesystems — blocked (run it manually if you really mean it)"))
        };
        match p {
            "fdisk" | "sfdisk" | "gdisk" => {
                if has("-l") || has("--list") || (p == "sfdisk" && (has("-d") || has("--dump"))) {
                    Ok(())
                } else {
                    blocked()
                }
            }
            "sgdisk" => {
                if has("-p") || has("--print") || has("-i") || has("--info") {
                    Ok(())
                } else {
                    blocked()
                }
            }
            "parted" => {
                let read_only = has("-l") || has("--list") || has("print");
                let writes = has_any(c.args, &["mklabel", "mktable", "mkpart", "rm", "resizepart", "resize", "rescue", "mkfs", "name", "set", "toggle"]);
                if read_only && !writes {
                    Ok(())
                } else {
                    blocked()
                }
            }
            "wipefs" => {
                let wipes = c.args.iter().any(|a| {
                    a == "--all" || a.starts_with("--offset") || (a.starts_with('-') && !a.starts_with("--") && (a.contains('a') || a.contains('o')))
                });
                if wipes {
                    blocked()
                } else {
                    Ok(())
                }
            }
            "mkswap" => {
                if c.args.iter().any(|a| a.starts_with("/dev/")) {
                    blocked()
                } else {
                    Ok(())
                }
            }
            "zpool" | "zfs" => {
                if has_any(c.args, &["destroy", "labelclear"]) {
                    blocked()
                } else {
                    Ok(())
                }
            }
            "cryptsetup" => {
                if has_any(c.args, &["luksFormat", "erase", "luksErase", "reencrypt", "luksKillSlot", "luksRemoveKey"]) {
                    blocked()
                } else {
                    Ok(())
                }
            }
            "hdparm" => {
                let bad = c.args.iter().any(|a| {
                    a.contains("security-erase") || a.contains("sanitize") || a.contains("trim-sector") || a.contains("fwdownload") || a == "--dco-restore"
                });
                if bad {
                    blocked()
                } else {
                    Ok(())
                }
            }
            "nvme" => {
                if has_any(c.args, &["format", "sanitize", "delete-ns", "fw-download", "fw-commit"]) {
                    blocked()
                } else {
                    Ok(())
                }
            }
            "badblocks" => {
                if has("-w") {
                    blocked()
                } else {
                    Ok(())
                }
            }
            _ => blocked(),
        }
    }
}
