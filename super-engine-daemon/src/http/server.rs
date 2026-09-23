// SPDX-License-Identifier: GPL-3.0-only
//! The daemon's listeners: its Unix socket, and the loopback TCP port a
//! browser can reach.
//!
//! Every connection is admitted here before the daemon's router sees it. A
//! caller on the Unix socket is named by the kernel (`SO_PEERCRED`); a caller
//! on TCP stays anonymous until the origin gate
//! ([`require_allowed_origin`](crate::auth::middleware::require_allowed_origin))
//! checks its `Origin` against the user's allowlist. Either way the result is
//! a [`PeerInfo`] on the request, which is all the auth layer reads.

use crate::http::PeerInfo;
use crate::http::origins::admits_any_origin;
use crate::resource_management::ResourceManager;
use anyhow::{Context, Result};
use axum::http::StatusCode;
use log::{info, warn};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::broadcast;

/// Where a daemon serves, and what it serves there.
pub struct Listeners {
    /// The Unix socket, always served.
    pub socket_path: PathBuf,
    /// The loopback address of the TCP listener, or `None` when the user
    /// turned it off.
    pub tcp: Option<SocketAddr>,
    /// The user's `[http.tcp].allowed_origins`, only to say in the log which
    /// pages the TCP listener admits. The origin gate enforces it.
    pub allowed_origins: Vec<String>,
}

/// Create the parent directory, remove any stale socket file, bind the
/// Unix listener, and set socket permissions.
///
/// # Errors
/// Returns an error if directory creation, stale-file removal, socket
/// bind, or permission setting fails.
async fn bind_listener(socket_path: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Failed to create http socket directory")?;
    }
    if socket_path.exists() {
        tokio::fs::remove_file(socket_path)
            .await
            .context("Failed to remove existing http socket file")?;
    }

    let listener = UnixListener::bind(socket_path).context("Failed to bind http Unix socket")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if cfg!(debug_assertions) { 0o666 } else { 0o660 };
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(socket_path, perms)
            .context("Failed to set http socket permissions")?;
    }

    Ok(listener)
}

/// Build the router, bind the listeners, and serve until `shutdown_tx`
/// fires. Returns once the listeners are bound; the accept loop runs in a
/// background task.
///
/// `router` runs first, on the blocking pool. It is where a daemon builds its
/// state, which loads the persisted session store from the system keyring
/// ([`Auth::load`](crate::auth::Auth::load)); if the keyring is unavailable
/// the daemon refuses to start. Doing it before binding guarantees we never
/// leave a listening-but-unserviced socket behind on a keyring failure.
///
/// Returns the [`JoinHandle`](tokio::task::JoinHandle) of the accept-loop
/// task so the caller can supervise it: if the task ends before
/// `shutdown_tx` fires (panic, fatal `accept()` error, etc.), the caller
/// should treat the daemon as unreachable and exit.
///
/// # Errors
/// Returns an error if `router` fails, or the socket can't be created or
/// bound.
pub async fn serve<F>(
    listeners: Listeners,
    resource_manager: Arc<ResourceManager>,
    shutdown_tx: broadcast::Sender<()>,
    router: F,
) -> Result<tokio::task::JoinHandle<()>>
where
    F: FnOnce() -> Result<axum::Router> + Send + 'static,
{
    // That keyring read is a *blocking* secret-service call: on a locked
    // keyring it waits on the D-Bus unlock prompt for as long as the user
    // takes. Run it on the blocking pool and race it against the shutdown
    // signal so the wait stays interruptible — otherwise a Ctrl+C during
    // the unlock wait is swallowed (the caller's supervision `select!` is
    // only reached once startup finishes) and the daemon can't be stopped.
    let app = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        let load = tokio::task::spawn_blocking(router);
        tokio::select! {
            biased;
            _ = shutdown_rx.recv() => {
                // The blocking load is still parked on the keyring prompt;
                // a dropped runtime would join (and hang on) it, so exit
                // the process directly. Nothing is bound or in flight yet.
                info!("Shutdown requested during session-store load; exiting");
                std::process::exit(130);
            }
            res = load => res.context("session-store load task panicked")??,
        }
    };

    let socket_path = listeners.socket_path;
    let listener = bind_listener(&socket_path).await?;

    info!("HTTP daemon listening on socket: {}", socket_path.display());

    let tcp_listener = bind_tcp_listener(listeners.tcp, &listeners.allowed_origins).await;

    let cleanup_path = socket_path.clone();
    let handle = tokio::spawn(async move {
        let mut shutdown_rx = shutdown_tx.subscribe();
        let server_loop = async {
            loop {
                // `accept_tcp` is a never-ready future when the listener is
                // off, so the `select!` collapses to the Unix arm and a daemon
                // with no TCP listener behaves exactly as it did before there
                // was one.
                tokio::select! {
                    accepted = listener.accept() => {
                        let stream = match accepted {
                            Ok((stream, _addr)) => stream,
                            Err(e) => {
                                warn!("http accept failed: {e}");
                                continue;
                            }
                        };
                        let peer_cred = stream.peer_cred().ok();
                        // An out-of-range pid becomes `None` (not `0`) so it fails closed
                        // in `resolve_peer_identity` rather than resolving `/proc/0/exe`
                        // (audit 2 Tier 3 #9).
                        let resolved_process_id = peer_cred
                            .as_ref()
                            .and_then(tokio::net::unix::UCred::pid)
                            .and_then(|p| u32::try_from(p).ok());
                        let resolved_user_id = peer_cred.as_ref().map(tokio::net::unix::UCred::uid);
                        let peer = PeerInfo::unix(resolved_process_id, resolved_user_id);
                        serve_connection(stream, peer, &app, &resource_manager).await;
                    }
                    accepted = accept_tcp(tcp_listener.as_ref()) => {
                        let stream = match accepted {
                            Ok(stream) => stream,
                            Err(e) => {
                                warn!("http tcp accept failed: {e}");
                                continue;
                            }
                        };
                        // No credentials to read: this peer stays anonymous
                        // until `require_allowed_origin` checks its `Origin`
                        // against the user's list.
                        serve_connection(stream, PeerInfo::tcp(), &app, &resource_manager).await;
                    }
                }
            }
        };
        tokio::select! {
            biased;
            _ = shutdown_rx.recv() => {
                info!("HTTP server shutting down");
            }
            () = server_loop => {}
        }
        if cleanup_path.exists() {
            let _ = tokio::fs::remove_file(&cleanup_path).await;
        }
    });

    Ok(handle)
}

/// Bind the loopback TCP listener, the transport a browser can reach.
///
/// `None` means the daemon is reachable only over its Unix socket, where every
/// caller is peer-credential-verified — either because the user turned the
/// listener off, or because the port could not be bound.
///
/// **An unbindable port is logged, not fatal.** The listener is on by default,
/// so the commonest way to hit this is a second daemon on the same machine or
/// an unrelated process holding the port. Taking the whole daemon down for that
/// would trade a working Unix socket — the app, the applet, the CLI, all of
/// it — for an extra transport most users never call. The log line says what
/// was lost and why.
async fn bind_tcp_listener(
    addr: Option<SocketAddr>,
    allowed_origins: &[String],
) -> Option<tokio::net::TcpListener> {
    let addr = addr?;

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "Could not bind the HTTP TCP listener on {addr}: {e}. The daemon is \
                 still serving its Unix socket, so every native client works; only \
                 browser clients are unreachable. Free the port, or set a different \
                 [http.tcp].port."
            );
            return None;
        }
    };

    if admits_any_origin(allowed_origins) {
        info!("HTTP daemon listening on {addr}, open to any browser origin");
    } else if allowed_origins.is_empty() {
        warn!(
            "HTTP daemon listening on {addr}, but [http.tcp].allowed_origins is empty — \
             every browser request will be refused with origin_not_allowed."
        );
    } else {
        info!(
            "HTTP daemon listening on {addr} for origins: {}",
            allowed_origins.join(", ")
        );
    }
    Some(listener)
}

/// Accept on the TCP listener, or wait forever when there isn't one.
///
/// The pending branch is what lets the accept loop `select!` over both
/// transports unconditionally: with no TCP listener this arm simply never
/// completes, instead of the loop needing two shapes.
async fn accept_tcp(
    listener: Option<&tokio::net::TcpListener>,
) -> std::io::Result<tokio::net::TcpStream> {
    match listener {
        Some(l) => l.accept().await.map(|(stream, _addr)| stream),
        None => std::future::pending().await,
    }
}

/// Admit one accepted connection and serve it until it closes.
///
/// Generic over the stream so the Unix and TCP listeners share it: everything
/// from here on is plain HTTP, and the only thing that differed between the two
/// transports — who the caller is — has already been decided by the time
/// `peer` is passed in.
async fn serve_connection<S>(
    stream: S,
    peer: PeerInfo,
    app: &axum::Router,
    resource_manager: &Arc<ResourceManager>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 503 connection_rejected if the per-client cap is hit. We have to
    // write the response by hand here since axum isn't in the picture
    // yet — we never hand the stream to `serve_connection`.
    //
    // Registration is idempotent per client_id (uid:pid, or the origin
    // for a web caller): each call upserts the entry, the cap-check
    // passes when the entry already exists, and we deliberately do NOT
    // call `unregister_connection` on conn-close. The same client_id may
    // have multiple concurrent connections (e.g., /v1/events open while
    // /v1/ping fires), and an eager unregister would brick the sibling's
    // rate-limit lookup. Stale entries are pruned by
    // `ResourceManager::cleanup_task` after the configured idle timeout.
    let client_id = peer.client_id();
    if let Err(e) = resource_manager
        .register_connection(client_id.clone(), None)
        .await
    {
        warn!("connection rejected for {client_id}: {e}; sending 503 connection_rejected");
        let _ = write_oneshot_response(
            stream,
            StatusCode::SERVICE_UNAVAILABLE,
            "connection_rejected",
        )
        .await;
        return;
    }

    let app_for_conn = app.clone().layer(axum::Extension(peer));
    tokio::spawn(async move {
        let io = hyper_util::rt::TokioIo::new(stream);
        let svc = hyper_util::service::TowerToHyperService::new(app_for_conn);
        // `.with_upgrades()` is what makes an HTTP/1.1 protocol upgrade
        // actually happen. Without it hyper writes the `101 Switching
        // Protocols` response and then drops the connection instead of
        // handing the IO to `hyper::upgrade::on`, so a WebSocket route
        // completed its handshake and died before the first frame.
        if let Err(e) = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .with_upgrades()
            .await
        {
            log::debug!("http connection finished: {e}");
        }
    });
}

/// Write a single short HTTP/1.1 error response directly to the
/// stream, bypassing axum/hyper. Used in the accept loop when we
/// need to reject a connection (e.g., `503 connection_rejected`)
/// before handing the stream to `serve_connection`.
async fn write_oneshot_response<S>(
    mut stream: S,
    status: StatusCode,
    message: &str,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let body = format!(r#"{{"status":"error","message":"{message}"}}"#);
    let reason = status.canonical_reason().unwrap_or("Unknown");
    let raw = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status.as_u16(),
        reason,
        body.len(),
        body,
    );
    stream.write_all(raw.as_bytes()).await?;
    stream.shutdown().await
}
