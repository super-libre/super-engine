// SPDX-License-Identifier: GPL-3.0-only
//! What a daemon runs beside its own endpoints: who may call it, where its
//! secrets live, how often a caller may ask, and the sockets it serves on.
//!
//! - [`auth`]: session tokens, the consent dialog, and the guards every
//!   route sits behind.
//! - [`config`]: the daemon's `daemon.toml`, and its HTTP surface settings.
//! - [`backends`]: installed backends — finding them on disk, the models
//!   they serve, and the runtime policy a manifest is held to at discovery.
//! - [`devices`]: which device a model runs on, and the host's GPUs.
//! - [`download`]: provisioning a model's files before its backend loads it.
//! - [`download_progress`]: what a model load reports as it goes, and the
//!   loads in flight.
//! - [`download_stream`]: streaming a download to disk, hashing it on the
//!   way.
//! - [`events`]: the event bus, its core topics, and the `/events` stream.
//! - [`keyring`]: the system keyring, which holds the session tokens and each
//!   backend's API credentials.
//! - [`resource_management`]: the per-client connection cap and rate limit.
//! - [`language`]: which language a model is asked to work in, and the tags
//!   the global setting offers.
//! - [`load_gate`]: one model load at a time per slot, and the newest
//!   request wins.
//! - [`http`]: the Unix socket and loopback TCP listeners, what the daemon
//!   knows about each caller, and the error bodies the guards answer with.
//! - [`openapi`]: checks on the `OpenAPI` document a daemon generates.
//! - [`registry`]: the backend registry's index, what this host can run of
//!   it, and which build of a backend to install.
//! - [`self_update`]: whether the product has a newer release, and which
//!   installer to offer for it.
//! - [`shutdown`]: the signals that stop a daemon.
//! - [`subprocess`] (feature `subprocess`): running a backend shipped as a
//!   native binary, in a sandbox, over its `/v1` socket.
//! - [`wasm`] (feature `wasm`): running a backend shipped as a WASM
//!   component, and its realtime WebSocket host.
//!
//! Everything named after the product (the keyring service, the consent
//! helper, the environment variables) comes from the
//! [`ProductSpec`](super_engine_protocol::ProductSpec) the daemon passes in.

pub mod auth;
pub mod backends;
pub mod config;
pub mod devices;
pub mod download;
pub mod download_progress;
pub mod download_stream;
pub mod events;
pub mod http;
pub mod keyring;
pub mod language;
pub mod load_gate;
pub mod openapi;
pub mod registry;
pub mod resource_management;
pub mod self_update;
pub mod shutdown;
#[cfg(feature = "subprocess")]
pub mod subprocess;
#[cfg(feature = "wasm")]
pub mod wasm;
