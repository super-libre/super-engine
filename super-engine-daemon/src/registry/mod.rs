// SPDX-License-Identifier: GPL-3.0-only
//! The daemon side of the backend registry: fetching and caching the
//! product's `index.json` ([`client`]), the policy applied to what it serves
//! ([`index`]), what this machine can run ([`host`]), which build of a
//! backend and which variant of each model file it should get ([`compat`]),
//! and the record of which build is installed in a backend's directory
//! ([`installed`]). Resolving a custom repo or a staged local directory into an
//! index entry ([`custom_repo`], [`local_dir`]) and deciding which of a
//! backend's files survive an update ([`carry_over`]) are here too, as is the
//! install pipeline itself ([`install`]).

pub mod carry_over;
pub mod client;
pub mod compat;
pub mod custom_repo;
pub mod host;
pub mod index;
pub mod install;
pub mod installed;
pub mod local_dir;

use super_engine_protocol::ProductSpec;
use super_engine_spec::index::IndexBackend;

/// The running daemon, as the registry code needs to know it.
#[derive(Clone, Copy, Debug)]
pub struct Daemon {
    pub product: &'static ProductSpec,
    /// The daemon's own version (its `CARGO_PKG_VERSION`), which an index's
    /// `min_client` floor and an entry's contract are held against.
    pub version: &'static str,
    /// The `User-Agent` the daemon sends when it fetches.
    pub user_agent: &'static str,
}

/// The directory name a backend installs into.
///
/// The reverse-DNS `[backend].id` when the entry carries one, so every install
/// route — registry, custom repository, local directory — lands on the same
/// path for the same backend. Falls back to the registry key for an entry that
/// predates the identifier, which is where such a backend is already
/// installed.
///
/// `backend_id` arrives from `index.json` over the network. This function
/// does not assume the registry-client boundary
/// ([`retain_safe_backends`](index::retain_safe_backends)) already sanitized
/// it: it re-checks the value itself and falls back to the registry key
/// whenever `backend_id` is absent or malformed.
///
/// The check is the full `[backend].id` format rule
/// ([`super_engine_spec::backend_id::is_valid`]), not merely "usable as a
/// path component". `Manifest::parse` already holds every other route to that
/// rule, so anything looser here would make `index.json` the one input the
/// daemon accepts below its own contract — and the gap is not theoretical:
/// `.staging` is a perfectly good path component but names the shared staging
/// root every install writes through.
#[must_use]
pub fn install_dir_name<M>(entry: &IndexBackend<M>) -> &str {
    match entry.backend_id.as_deref() {
        Some(id) if super_engine_spec::backend_id::is_valid(id) => id,
        _ => &entry.id,
    }
}
