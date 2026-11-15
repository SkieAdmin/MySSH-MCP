//! Process execution with timeout, output caps and process-group cleanup.

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

pub struct ExecSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    pub max_output: usize,
}

pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub duration_ms: u128,
}

impl ExecOutput {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }

    pub fn status_line(&self) -> String {
        let mut s = match (self.exit_code, self.signal) {
            (Some(c), _) => format!("exit_code: {c}"),
            (None, Some(sig)) => format!("killed by signal {sig}"),
            _ => "exit_code: unknown".to_string(),
        };
        s.push_str(&format!(" | duration: {}ms", self.duration_ms));
        if self.timed_out {
            s.push_str(" | TIMED OUT (process group killed)");
        }
        if self.truncated {
            s.push_str(" | output truncated");
        }
        s
    }

    /// Text block returned to the AI.
    pub fn render(&self) -> String {
        let mut out = self.status_line();
        if !self.stdout.is_empty() {
            out.push_str("\n--- stdout ---\n");
            out.push_str(self.stdout.trim_end());
        }
        if !self.stderr.is_empty() {
            out.push_str("\n--- stderr ---\n");
            out.push_str(self.stderr.trim_end());
        }
        if self.stdout.is_empty() && self.stderr.is_empty() {
            out.push_str("\n(no output)");
        }
        out
    }
}

fn spawn_reader<R>(mut r: R, buf: Arc<Mutex<Vec<u8>>>, cap: usize, truncated: Arc<AtomicBool>) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut chunk = [0u8; 8192];
        loop {
            match r.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut b = buf.lock().unwrap_or_else(|p| p.into_inner());
                    let room = cap.saturating_sub(b.len());
                    let take = n.min(room);
                    b.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    })
}

#[cfg(unix)]
fn kill_group(pid: u32) {
    // SAFETY: plain libc call; a negative pid targets the whole process group.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_group(_pid: u32) {}

pub async fn run(spec: ExecSpec) -> Result<ExecOutput, String> {
    let mut std_cmd = std::process::Command::new(&spec.program);
    std_cmd.args(&spec.args);
    if let Some(dir) = &spec.cwd {
        std_cmd.current_dir(dir);
    }
    std_cmd
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("TERM", "dumb")
        .env("PAGER", "cat")
        .env("GIT_PAGER", "cat")
        .env("SYSTEMD_PAGER", "")
        .env("SYSTEMD_COLORS", "0")
        .env("NO_COLOR", "1");
    if std::env::var_os("HOME").is_none() {
        std_cmd.env("HOME", "/root");
    }
    if std::env::var_os("PATH").is_none() {
        std_cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin");
    }
    for (k, v) in &spec.env {
        std_cmd.env(k, v);
    }
    std_cmd
        .stdin(if spec.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
    }
    let mut cmd = tokio::process::Command::from(std_cmd);
    cmd.kill_on_drop(true);

    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| format!("failed to start `{}`: {e}", spec.program))?;
    let pid = child.id();

    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let err_buf = Arc::new(Mutex::new(Vec::new()));
    let truncated = Arc::new(AtomicBool::new(false));
    let mut h_out = child
        .stdout
        .take()
        .map(|s| spawn_reader(s, out_buf.clone(), spec.max_output, truncated.clone()));
    let mut h_err = child
        .stderr
        .take()
        .map(|s| spawn_reader(s, err_buf.clone(), spec.max_output, truncated.clone()));

    if let (Some(input), Some(mut stdin)) = (spec.stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        });
    }

    let mut timed_out = false;
    let mut exit_code = None;
    let mut signal = None;
    match tokio::time::timeout(spec.timeout, child.wait()).await {
        Ok(Ok(status)) => {
            exit_code = status.code();
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                signal = status.signal();
            }
        }
        Ok(Err(e)) => return Err(format!("failed waiting for process: {e}")),
        Err(_) => {
            timed_out = true;
            if let Some(pid) = pid {
                kill_group(pid);
            }
            let _ = child.kill().await;
        }
    }

    // Background jobs (`cmd &`) may keep the pipes open: give readers a short grace period.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    if let Some(h) = h_out.as_mut() {
        let _ = tokio::time::timeout_at(deadline, h).await;
    }
    if let Some(h) = h_err.as_mut() {
        let _ = tokio::time::timeout_at(deadline, h).await;
    }
    if let Some(h) = h_out {
        h.abort();
    }
    if let Some(h) = h_err {
        h.abort();
    }

    let take = |b: &Arc<Mutex<Vec<u8>>>| {
        let v = b.lock().unwrap_or_else(|p| p.into_inner());
        String::from_utf8_lossy(&v).into_owned()
    };
    Ok(ExecOutput {
        stdout: take(&out_buf),
        stderr: take(&err_buf),
        exit_code,
        signal,
        timed_out,
        truncated: truncated.load(Ordering::Relaxed),
        duration_ms: started.elapsed().as_millis(),
    })
}

/// Helper: is `program` available in PATH?
pub fn which(program: &str) -> bool {
    let path = std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    path.split(':').any(|dir| std::path::Path::new(dir).join(program).is_file())
}
