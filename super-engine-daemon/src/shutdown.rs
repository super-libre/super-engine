// SPDX-License-Identifier: GPL-3.0-only
//! The signals that stop a daemon.

use std::future::Future;
use tokio::signal::unix::{Signal, SignalKind};

/// Start watching for SIGINT and SIGTERM, and return a future that completes
/// when either arrives.
///
/// Both, because `systemctl stop` and a plain `kill` send SIGTERM. A daemon
/// that watches only SIGINT (`tokio::signal::ctrl_c`) dies to SIGTERM's
/// default disposition and skips its graceful path. That path is what stops
/// a subprocess backend's `systemd-run --user` unit, which is not a child in
/// the daemon's cgroup, so nothing else reaps it: the backend stays up with
/// its whole model resident until `subprocess::cleanup_orphans` sweeps it at
/// the next start.
///
/// The handlers are installed by this call, not when the future is first
/// polled, so a signal that arrives while the daemon is still starting is
/// caught too. Call it early in `main`, inside the runtime.
///
/// A signal that cannot be watched is logged, and the future waits on the
/// other. It does not panic: it usually runs in a spawned task, where a panic
/// would leave a daemon that can never shut down at all.
pub fn signal() -> impl Future<Output = ()> + Send {
    let mut interrupt = watch(SignalKind::interrupt(), "SIGINT");
    let mut terminate = watch(SignalKind::terminate(), "SIGTERM");
    async move {
        tokio::select! {
            () = received(interrupt.as_mut()) => {
                log::info!("Received SIGINT, initiating shutdown...");
            }
            () = received(terminate.as_mut()) => {
                log::info!("Received SIGTERM, initiating shutdown...");
            }
        }
    }
}

fn watch(kind: SignalKind, name: &str) -> Option<Signal> {
    tokio::signal::unix::signal(kind)
        .inspect_err(|e| log::error!("cannot listen for {name}: {e}"))
        .ok()
}

/// Completes when `signal` next arrives, and never for a signal that could
/// not be watched.
async fn received(signal: Option<&mut Signal>) {
    match signal {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
}
