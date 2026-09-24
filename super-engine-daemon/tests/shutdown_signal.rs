// SPDX-License-Identifier: GPL-3.0-only
//! `shutdown::signal` ends its wait on SIGTERM as well as SIGINT.
//!
//! This test signals its own process, so it has a binary to itself: were the
//! handlers missing, the default disposition would kill the process and fail
//! the run loudly rather than pass.

use std::time::Duration;

/// Send `signal` to this process and expect a fresh wait to end on it.
async fn ends_on(signal: libc::c_int) {
    let wait = super_engine_daemon::shutdown::signal();
    // SAFETY: `kill` on this process's own pid, with a signal the call above
    // has just installed a handler for.
    let sent = unsafe { libc::kill(libc::getpid(), signal) };
    assert_eq!(sent, 0, "kill(self, {signal}) failed");
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap_or_else(|_| panic!("the wait did not end on signal {signal}"));
}

/// One test, not two, so the two signals are sent in turn: a wait started in a
/// parallel test would also see the other's signal.
#[tokio::test]
async fn sigterm_and_sigint_each_end_the_wait() {
    ends_on(libc::SIGTERM).await;
    ends_on(libc::SIGINT).await;
}
