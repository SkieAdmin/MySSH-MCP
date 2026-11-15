#![recursion_limit = "512"]
//! MySSH-MCP — a guarded MCP server that lets AI assistants manage a Linux server as root,
//! with a safety policy in front of every command and a complete audit log.

mod audit;
mod auth;
mod config;
mod exec;
mod http;
mod mcp;
mod policy;
mod setup;
mod state;
mod stdio;
mod tools;

use clap::{Parser, Subcommand};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "myssh-mcp",
    version,
    about = "MySSH-MCP: guarded MCP server for AI-driven server management (root, policy-checked, audited)"
)]
struct Cli {
    /// Path of the configuration file
    #[arg(long, global = true, default_value = config::DEFAULT_CONFIG_PATH)]
    config: String,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the MCP server over HTTP (default; used by the systemd service)
    Serve,
    /// Speak MCP over stdin/stdout, e.g. `ssh -T root@host myssh-mcp stdio`
    Stdio,
    /// Install / update: API key, config, systemd service, log rotation (run as root)
    Setup {
        /// Listen address (0.0.0.0 = public, 127.0.0.1 = behind a reverse proxy / tunnel)
        #[arg(long)]
        bind: Option<String>,
        /// Listen port (default 8765)
        #[arg(long)]
        port: Option<u16>,
        /// Public IP or hostname written into the connection guide
        #[arg(long)]
        public_host: Option<String>,
        /// Always generate a new API key
        #[arg(long)]
        new_key: bool,
        /// Do not start the service
        #[arg(long)]
        no_start: bool,
    },
    /// Generate a new API key (the old key stops working immediately)
    RotateKey,
    /// Check a shell command against the safety policy (exit code 2 = denied)
    Check {
        command: String,
        #[arg(long, default_value = "/root")]
        cwd: String,
    },
    /// Check an SQL query against the safety policy (exit code 2 = denied)
    CheckSql { query: String },
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start async runtime: {e}"))
}

fn load_policy(config_path: &str) -> Result<policy::Policy, String> {
    let cfg = config::Config::load_or_default(config_path)?;
    policy::Policy::new(&cfg.policy, &cfg.logging.log_file, cfg.server.port)
}

fn print_verdict(v: policy::Verdict) -> i32 {
    match v {
        Ok(()) => {
            println!("ALLOWED");
            0
        }
        Err(reason) => {
            println!("DENIED: {reason}");
            2
        }
    }
}

fn run(cli: Cli) -> Result<i32, String> {
    let config_path = cli.config;
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Serve => runtime()?.block_on(async {
            let cfg = config::Config::load(&config_path)?;
            if cfg.server.api_key_sha256.len() != 64 {
                return Err("no API key configured — run `sudo myssh-mcp setup` first".to_string());
            }
            let st = Arc::new(state::AppState::new(cfg, true)?);
            http::serve(st).await?;
            Ok::<i32, String>(0)
        }),
        Cmd::Stdio => runtime()?.block_on(async {
            let cfg = config::Config::load_or_default(&config_path)?;
            let st = Arc::new(state::AppState::new(cfg, false)?);
            stdio::serve(st).await?;
            Ok::<i32, String>(0)
        }),
        Cmd::Setup { bind, port, public_host, new_key, no_start } => {
            setup::run_setup(setup::SetupOpts { config_path, bind, port, public_host, new_key, no_start })?;
            Ok(0)
        }
        Cmd::RotateKey => {
            setup::rotate_key(&config_path)?;
            Ok(0)
        }
        Cmd::Check { command, cwd } => {
            let p = load_policy(&config_path)?;
            Ok(print_verdict(p.check_command(&command, &cwd)))
        }
        Cmd::CheckSql { query } => {
            let p = load_policy(&config_path)?;
            Ok(print_verdict(p.check_sql(&query)))
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("myssh-mcp: {e}");
            1
        }
    };
    std::process::exit(code);
}
