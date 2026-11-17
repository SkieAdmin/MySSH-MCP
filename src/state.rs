use crate::audit::AuditLog;
use crate::auth::RateLimiter;
use crate::config::Config;
use crate::policy::Policy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Shared server state.
pub struct AppState {
    pub cfg: Config,
    pub policy: Policy,
    pub audit: AuditLog,
    pub limiter: RateLimiter,
    pub sem: Semaphore,
    /// Last automatic database backup per database target: (when, backup id).
    pub db_last_backup: Mutex<HashMap<String, (Instant, String)>>,
    /// Serializes backup / restore runs so two dumps never race on the same database.
    pub db_lock: tokio::sync::Mutex<()>,
}

impl AppState {
    pub fn new(cfg: Config, echo_stderr: bool) -> Result<AppState, String> {
        let policy = Policy::new(&cfg.policy, &cfg.logging.log_file, cfg.server.port)?;
        let audit = AuditLog::open(&cfg.logging.log_file, echo_stderr);
        let sem = Semaphore::new(cfg.limits.max_concurrent_commands.max(1));
        Ok(AppState {
            cfg,
            policy,
            audit,
            limiter: RateLimiter::new(),
            sem,
            db_last_backup: Mutex::new(HashMap::new()),
            db_lock: tokio::sync::Mutex::new(()),
        })
    }
}
