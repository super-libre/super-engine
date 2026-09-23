// SPDX-License-Identifier: GPL-3.0-only
//! A client of a daemon built on super-engine: the HTTP transport over the
//! daemon's Unix socket, the session tokens clients keep in the keyring, the
//! retry policy, and the self-healing `/events` subscription the widgets run
//! on.
//!
//! Each product's own endpoints are built on
//! [`http_client::transport`] in that product's repository.

pub mod http_client;
pub mod retry;
pub mod session;
pub mod widget_subscription;
