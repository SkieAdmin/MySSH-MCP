//! MCP Streamable HTTP transport (POST /mcp, JSON responses) with API-key authentication.

use crate::audit::{q, Kind};
use crate::auth;
use crate::mcp;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub async fn serve(st: Arc<AppState>) -> Result<(), String> {
    let app = Router::new()
        .route("/mcp", post(mcp_post).get(not_allowed).delete(not_allowed))
        .route("/", post(mcp_post))
        .route("/health", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(st.clone());

    let bind = st.cfg.server.bind.trim_matches(|c: char| c == '[' || c == ']');
    let ip: IpAddr = bind.parse().map_err(|e| format!("invalid bind address `{bind}`: {e}"))?;
    let addr = SocketAddr::new(ip, st.cfg.server.port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    st.audit.system(&format!(
        "MySSH-MCP v{} listening on http://{addr}/mcp (audit log: {})",
        env!("CARGO_PKG_VERSION"),
        st.audit.path()
    ));
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))?;
    st.audit.system("MySSH-MCP stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

async fn not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        "MySSH-MCP speaks MCP Streamable HTTP: send JSON-RPC with POST",
    )
        .into_response()
}

fn client_ip(st: &AppState, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if st.cfg.server.trust_proxy {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok());
        if let Some(ip) = forwarded {
            return ip;
        }
        if let Some(ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok()) {
            return ip;
        }
    }
    peer.ip()
}

fn rpc_error(status: StatusCode, code: i64, msg: &str) -> Response {
    (status, Json(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": code, "message": msg } }))).into_response()
}

async fn mcp_post(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(&st, &headers, peer);
    let client = ip.to_string();

    if let Some(secs) = st.limiter.banned(ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, secs.to_string())],
            "too many failed authentication attempts",
        )
            .into_response();
    }

    let authz = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    let x_api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());
    let authorized = auth::extract_key(authz, x_api_key)
        .map(|k| auth::verify(&k, &st.cfg.server.api_key_sha256))
        .unwrap_or(false);
    if !authorized {
        let banned = st.limiter.failure(ip);
        let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
        let reason = if authz.is_none() && x_api_key.is_none() { "missing API key" } else { "invalid API key" };
        st.audit.log(
            Kind::AuthFail,
            &client,
            "",
            &format!(
                "reason={} user_agent={}{}",
                q(reason),
                q(ua),
                if banned { " action=\"IP banned for 15 minutes\"" } else { "" }
            ),
        );
        let mut resp = rpc_error(StatusCode::UNAUTHORIZED, -32001, "Unauthorized: missing or invalid API key");
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer realm=\"MySSH-MCP\""),
        );
        return resp;
    }
    st.limiter.success(ip);

    let parsed = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(mcp::parse_error(&e.to_string()))).into_response(),
    };
    match mcp::handle_body(&st, parsed, &client).await {
        Some(v) => (StatusCode::OK, Json(v)).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}
