// SPDX-License-Identifier: GPL-3.0-only
//! One entry of `registry/registry.toml` — the source of truth for the
//! installable-backend catalog. The table key is the backend id
//! (ascii lowercase, digits, `-`, `_`). See `registry/README.md`.

use serde::Deserialize;

use crate::forge::Forge;

/// A `registry.toml` entry: where a backend's releases live and how the
/// indexer selects them.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Entry {
    /// Reverse-DNS identifier for the backend, e.g. `com.example.voxtral`.
    /// Must equal the `[backend].id` of the release manifest this entry points
    /// at. Required — the generated `registry.schema.json` says so, and the
    /// indexer refuses an entry without one.
    ///
    /// `Option` only because six entries predate the requirement and their
    /// published manifests declare no `[backend].id` to match against. The
    /// indexer tolerates exactly those (`registry_toml::GRANDFATHERED`) so the
    /// catalog keeps building; the schema flags them, which is the backlog.
    #[serde(default)]
    pub id: Option<String>,
    /// Repository hosting the backend, as `<host>/<owner>/<repo>` (e.g.
    /// `github.com/<owner>/<repo>`). The indexer queries this repo's releases
    /// to discover versions.
    pub repo: String,
    /// The forge (git host) that publishes this backend's releases. See
    /// [`Forge`] for accepted values and the required/explicit policy.
    pub forge: Forge,
    /// Path within the repo to the directory containing the backend's
    /// `backend.toml` (default: repo root). Must be a safe relative path:
    /// no `..`, no leading `/`, no backslashes.
    #[serde(default)]
    pub subdir: Option<String>,
    /// Release-tag prefix used to select this backend's releases (e.g.
    /// `openai-` matches tags like `openai-v1.2.0`). Required when multiple
    /// entries share the same `repo` (monorepo); each shared-repo prefix must
    /// be distinct and may not itself be a prefix of another.
    #[serde(default)]
    pub tag_prefix: Option<String>,
    /// Version ceiling (yank). The indexer ignores any release whose resolved
    /// version is greater than this value. Use it to pin away from a bad
    /// release without removing the entry.
    #[serde(default)]
    pub max_version: Option<String>,
    /// When `true`, delists the backend while keeping its row for audit
    /// (prevents another submitter from claiming the id). Removed entries are
    /// skipped by the indexer.
    #[serde(default)]
    pub removed: bool,
    /// Human-readable note explaining why the entry was removed.
    #[serde(default)]
    pub removed_reason: Option<String>,
}
