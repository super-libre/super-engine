// SPDX-License-Identifier: GPL-3.0-only
//! What a daemon runs beside its own endpoints: who may call it, where its
//! secrets live, how often a caller may ask, and the sockets it serves on.
//!
//! - [`auth`]: session tokens, the consent dialog, and the guards every
//!   route sits behind.
//! - [`download_stream`]: streaming a download to disk, hashing it on the
//!   way.
//! - [`events`]: the event bus, its core topics, and the `/events` stream.
//! - [`keyring`]: the system keyring, which holds the session tokens and each
//!   backend's API credentials.
//! - [`resource_management`]: the per-client connection cap and rate limit.
//! - [`http`]: the Unix socket and loopback TCP listeners, what the daemon
//!   knows about each caller, and the error bodies the guards answer with.
//! - [`openapi`]: checks on the `OpenAPI` document a daemon generates.
//! - [`self_update`]: whether the product has a newer release, and which
//!   installer to offer for it.
//!
//! Everything named after the product (the keyring service, the consent
//! helper, the environment variables) comes from the
//! [`ProductSpec`](super_engine_protocol::ProductSpec) the daemon passes in.

pub mod auth;
pub mod download_stream;
pub mod events;
pub mod http;
pub mod keyring;
pub mod openapi;
pub mod resource_management;
pub mod self_update;
