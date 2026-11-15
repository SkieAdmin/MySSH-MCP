//! system_info / service_control

use super::{arg_str, arg_u64, denied, run_logged, ToolOutput};
use crate::audit::{q, Kind};
use crate::exec::{self, ExecSpec};
use crate::state::AppState;
use serde_json::Value;
use std::time::Duration;

fn read_trim(path: &str) -> String {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn os_name() -> String {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn human_uptime() -> String {
    let secs = read_trim("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;
    format!("{}d {}h {}m", secs / 86_400, (secs % 86_400) / 3_600, (secs % 3_600) / 60)
}

fn meminfo() -> String {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let get = |key: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    let (total, avail) = (get("MemTotal:"), get("MemAvailable:"));
    let (swap_total, swap_free) = (get("SwapTotal:"), get("SwapFree:"));
    format!(
        "RAM {} MiB used / {} MiB total ({} MiB available) | Swap {} MiB used / {} MiB",
        total.saturating_sub(avail) / 1024,
        total / 1024,
        avail / 1024,
        swap_total.saturating_sub(swap_free) / 1024,
        swap_total / 1024
    )
}

async fn quick(program: &str, args: &[&str]) -> String {
    if !exec::which(program) {
        return format!("({program} not installed)");
    }
    let spec = ExecSpec {
        program: program.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        cwd: Some("/".into()),
        env: Vec::new(),
        stdin: None,
        timeout: Duration::from_secs(10),
        max_output: 64 * 1024,
    };
    match exec::run(spec).await {
        Ok(o) if o.success() => o.stdout.trim_end().to_string(),
        Ok(o) => format!("{}\n{}", o.stdout.trim_end(), o.stderr.trim_end()).trim().to_string(),
        Err(e) => e,
    }
}

pub async fn system_info(st: &AppState, client: &str) -> ToolOutput {
    st.audit.log(Kind::Granted, client, "system_info", "cmd=\"(built-in read-only overview)\"");
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let mut out = String::new();
    out.push_str(&format!("Hostname : {}\n", read_trim("/proc/sys/kernel/hostname")));
    out.push_str(&format!("OS       : {}\n", os_name()));
    out.push_str(&format!("Kernel   : {}\n", read_trim("/proc/sys/kernel/osrelease")));
    out.push_str(&format!("Uptime   : {}\n", human_uptime()));
    out.push_str(&format!("Load avg : {}\n", read_trim("/proc/loadavg")));
    out.push_str(&format!("CPUs     : {cpus}\n"));
    out.push_str(&format!("Memory   : {}\n", meminfo()));
    out.push_str("\n== Disks ==\n");
    out.push_str(&quick("df", &["-h", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"]).await);
    out.push_str("\n\n== Listening TCP ports ==\n");
    out.push_str(&quick("ss", &["-tlnp"]).await);
    out.push_str("\n\n== Docker containers ==\n");
    out.push_str(&quick("docker", &["ps", "-a", "--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}"]).await);
    out.push_str("\n\n== Failed systemd units ==\n");
    out.push_str(&quick("systemctl", &["--failed", "--no-pager", "--no-legend"]).await);
    ToolOutput::ok(out)
}

fn valid_unit(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "@._:-\\".contains(c))
}

pub async fn service_control(st: &AppState, args: &Value, client: &str) -> ToolOutput {
    const TOOL: &str = "service_control";
    let (Some(action), Some(service)) = (arg_str(args, "action"), arg_str(args, "service")) else {
        return ToolOutput::err("missing required arguments `action` and `service`");
    };
    const ACTIONS: &[&str] = &[
        "status", "start", "stop", "restart", "reload", "enable", "disable", "is-active", "is-enabled", "logs",
    ];
    if !ACTIONS.contains(&action) {
        return ToolOutput::err(format!("unknown action `{action}` (allowed: {})", ACTIONS.join(", ")));
    }
    if !valid_unit(service) {
        return ToolOutput::err("invalid service name");
    }
    let (program, argv): (&str, Vec<String>) = if action == "logs" {
        let lines = arg_u64(args, "lines").unwrap_or(100).clamp(1, 5000);
        ("journalctl", vec!["-u".into(), service.into(), "-n".into(), lines.to_string(), "--no-pager".into()])
    } else {
        ("systemctl", vec![action.into(), service.into(), "--no-pager".into(), "-l".into()])
    };
    let display = format!("{program} {}", argv.join(" "));
    let what = format!("cmd={}", q(&display));
    if let Err(reason) = st.policy.check_command(&display, "/") {
        return denied(st, client, TOOL, &what, &reason);
    }
    st.audit.log(Kind::Granted, client, TOOL, &what);
    let read_only = matches!(action, "status" | "is-active" | "is-enabled" | "logs");
    let spec = ExecSpec {
        program: program.into(),
        args: argv,
        cwd: Some("/".into()),
        env: Vec::new(),
        stdin: None,
        timeout: Duration::from_secs(120),
        max_output: st.cfg.limits.max_output_bytes,
    };
    run_logged(st, client, TOOL, spec, !read_only).await
}
