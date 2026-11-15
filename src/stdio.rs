//! MCP over stdin/stdout (newline-delimited JSON-RPC), e.g. `ssh -T root@host myssh-mcp stdio`.
//! Authentication is done by SSH; the same policy and audit log apply.

use crate::mcp;
use crate::state::AppState;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn serve(st: Arc<AppState>) -> Result<(), String> {
    let client = match std::env::var("SSH_CLIENT") {
        Ok(v) => format!("ssh:{}", v.split_whitespace().next().unwrap_or("?")),
        Err(_) => "stdio".to_string(),
    };
    st.audit.log(crate::audit::Kind::System, &client, "", "msg=\"stdio session started\"");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(line) = rx.recv().await {
            if out.write_all(line.as_bytes()).await.is_err() || out.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = out.flush().await;
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let (st, tx, client) = (st.clone(), tx.clone(), client.clone());
        tokio::spawn(async move {
            let resp = match serde_json::from_str::<Value>(&line) {
                Ok(v) => mcp::handle_body(&st, v, &client).await,
                Err(e) => Some(mcp::parse_error(&e.to_string())),
            };
            if let Some(r) = resp {
                let _ = tx.send(r.to_string());
            }
        });
    }
    drop(tx);
    let _ = writer.await;
    st.audit.log(crate::audit::Kind::System, &client, "", "msg=\"stdio session ended\"");
    Ok(())
}
