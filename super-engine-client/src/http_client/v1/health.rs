// SPDX-License-Identifier: GPL-3.0-only
use super::super::internal::error::HttpResult;
use super::super::internal::transport;
use serde::de::DeserializeOwned;
use std::path::PathBuf;

/// The one field of a `/ping` answer this client reads.
#[derive(serde::Deserialize)]
struct PingReply {
    #[serde(default)]
    message: Option<String>,
}

/// `GET /ping` — liveness check.
///
/// # Errors
/// Returns an error if the daemon HTTP listener isn't reachable or the
/// response can't be parsed.
pub async fn ping(socket_path: PathBuf, token: &str) -> HttpResult<String> {
    let req = transport::build_get("/ping", Some(token))?;
    let resp = transport::send_request::<PingReply>(&socket_path, req).await?;
    Ok(resp
        .message
        .unwrap_or_else(|| "Daemon is running".to_string()))
}

/// `GET /status` — current model + device, read into the product's response
/// type `T`.
///
/// # Errors
/// Returns an error if the daemon HTTP listener isn't reachable or the
/// response can't be parsed.
pub async fn status<T: DeserializeOwned>(socket_path: PathBuf, token: &str) -> HttpResult<T> {
    let req = transport::build_get("/status", Some(token))?;
    transport::send_request::<T>(&socket_path, req).await
}
