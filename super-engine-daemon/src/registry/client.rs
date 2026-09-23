// SPDX-License-Identifier: GPL-3.0-only
//! Fetch and cache the registry's `index.json`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use super_engine_spec::index::Index;
use thiserror::Error;

use crate::registry::Daemon;
use crate::registry::index::{retain_safe_backends, warn_if_client_too_old};

/// How long a fetched index is served before the next request refetches it.
pub const DEFAULT_TTL: Duration = Duration::from_hours(6);

/// The variable (`SUPER_STT_REGISTRY_URL`) that points a daemon at another
/// index. Only an `https` URL, or a loopback one, is accepted.
pub const REGISTRY_URL: &str = "REGISTRY_URL";

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("registry unavailable and no cache")]
    Unavailable,
}

/// A product's registry index, fetched over the network and cached on disk.
/// Generic over the product's index-model fields, as [`Index`] is.
#[derive(Clone)]
pub struct Client<M> {
    /// Whose index this is, and the version its `min_client` floor is held
    /// against.
    daemon: Daemon,
    url: String,
    http: reqwest::Client,
    cache_path: PathBuf,
    ttl: Duration,
    state: Arc<RwLock<Option<Cached<M>>>>,
}

#[derive(Clone)]
struct Cached<M> {
    index: Index<M>,
    etag: Option<String>,
    fetched_at: SystemTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    etag: Option<String>,
    fetched_at_secs: u64,
    index: serde_json::Value,
}

impl<M: Clone + DeserializeOwned + Send + Sync + 'static> Client<M> {
    /// # Panics
    /// Panics if the `reqwest` client cannot be built (should never happen with default settings).
    #[must_use]
    pub fn new(daemon: Daemon, url: impl Into<String>, cache_path: PathBuf, ttl: Duration) -> Self {
        Self {
            daemon,
            url: url.into(),
            http: super_engine_forge::http::short_client(daemon.user_agent),
            cache_path,
            ttl,
            state: Arc::default(),
        }
    }

    /// The product's published index, or the one its [`REGISTRY_URL`]
    /// variable names, cached in the product's cache directory.
    #[must_use]
    pub fn from_env(daemon: Daemon) -> Self {
        let product = daemon.product;
        let var = product.env(REGISTRY_URL);
        let url = match std::env::var(&var) {
            Ok(v) if super_engine_forge::accept_base_url(&v) => v,
            Ok(v) => {
                log::warn!("ignoring insecure {var}={v:?}; using {}", product.index_url);
                product.index_url.into()
            }
            Err(_) => product.index_url.into(),
        };
        let cache_dir = super_engine_protocol::paths::cache_dir(product);
        // The cache dir is created lazily by `persist_to_disk` on the first
        // successful fetch (on a blocking thread), not eagerly here (Tier 3 #3).
        Self::new(
            daemon,
            url,
            cache_dir.join("registry-index.json"),
            DEFAULT_TTL,
        )
    }

    /// Get the index. Uses memory → file cache → network in that order; falls
    /// back to whichever is freshest if the network is down.
    ///
    /// # Errors
    /// Returns `ClientError::Unavailable` when the network is unreachable and there is no
    /// cached index on disk.
    pub async fn get(&self) -> Result<Index<M>, ClientError> {
        {
            let guard = self.state.read();
            if let Some(c) = guard.as_ref()
                && c.fetched_at.elapsed().unwrap_or_default() < self.ttl
            {
                return Ok(c.index.clone());
            }
        }
        if let Ok(idx) = self.refresh().await {
            Ok(idx)
        } else {
            let guard = self.state.read();
            if let Some(c) = guard.as_ref() {
                return Ok(c.index.clone());
            }
            Err(ClientError::Unavailable)
        }
    }

    /// Force-refresh. Pre-populates the in-memory cache from the on-disk
    /// cache on first call (so the daemon can start cold and still serve
    /// the prior index without a successful network fetch).
    ///
    /// # Errors
    /// Returns a `ClientError` on network failure, I/O error, or JSON parse error.
    /// Returns `ClientError::Unavailable` if the server answers with an unsolicited
    /// `304 Not Modified` and there is no cached index to fall back on.
    pub async fn refresh(&self) -> Result<Index<M>, ClientError> {
        // Load from disk if memory is empty.
        let etag = {
            let need_load = self.state.read().is_none();
            if need_load {
                // Read + parse the on-disk cache off the async worker (Tier 3 #3).
                let cache_path = self.cache_path.clone();
                let loaded = tokio::task::spawn_blocking(move || load_from_disk::<M>(&cache_path))
                    .await
                    .map_err(|e| ClientError::Io(std::io::Error::other(e)))??;
                if let Some((mut idx, etag)) = loaded {
                    warn_if_client_too_old(&idx, self.daemon.product, self.daemon.version);
                    retain_safe_backends(&mut idx);
                    self.state.write().replace(Cached {
                        index: idx,
                        etag: etag.clone(),
                        fetched_at: SystemTime::UNIX_EPOCH,
                    });
                    etag
                } else {
                    None
                }
            } else {
                self.state.read().as_ref().and_then(|c| c.etag.clone())
            }
        };

        let mut req = self.http.get(&self.url);
        if let Some(e) = &etag {
            req = req.header("If-None-Match", e);
        }
        let resp = req.send().await?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            // A 304 is only valid as the answer to our conditional request, so a
            // cached index should exist to refresh. If it doesn't — a misbehaving
            // proxy replying 304 when we sent no `If-None-Match` — treat it as
            // unavailable rather than unwrapping `None` and panicking the daemon.
            let mut guard = self.state.write();
            let Some(c) = guard.as_mut() else {
                return Err(ClientError::Unavailable);
            };
            c.fetched_at = SystemTime::now();
            return Ok(c.index.clone());
        }

        let resp = resp.error_for_status()?;
        let new_etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let bytes = resp.bytes().await?;
        let mut index: Index<M> = serde_json::from_slice(&bytes)?;
        retain_safe_backends(&mut index);
        warn_if_client_too_old(&index, self.daemon.product, self.daemon.version);
        let cached = Cached {
            index: index.clone(),
            etag: new_etag,
            fetched_at: SystemTime::now(),
        };
        self.state.write().replace(cached.clone());
        // Serialize + atomic-write the cache off the async worker (Tier 3 #3).
        let cache_path = self.cache_path.clone();
        let etag = cached.etag.clone();
        let fetched_at = cached.fetched_at;
        tokio::task::spawn_blocking(move || persist_to_disk(&cache_path, etag, fetched_at, &bytes))
            .await
            .map_err(|e| ClientError::Io(std::io::Error::other(e)))??;
        Ok(index)
    }
}

/// An index read back from the disk cache, with the `ETag` it was fetched
/// under.
type Loaded<M> = (Index<M>, Option<String>);

/// Read + parse the on-disk index cache. Synchronous `std::fs` + `serde_json`, so
/// the async refresh path runs it on a blocking thread (audit 2 Tier 3 #3).
///
/// The index comes back unfiltered; the caller applies the same policy as to
/// a fetched one.
fn load_from_disk<M: DeserializeOwned>(
    cache_path: &std::path::Path,
) -> Result<Option<Loaded<M>>, ClientError> {
    if !cache_path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(cache_path)?;
    let file: CacheFile = serde_json::from_slice(&bytes)?;
    let index: Index<M> = serde_json::from_value(file.index)?;
    Ok(Some((index, file.etag)))
}

/// Serialize + atomic-write the index cache. Synchronous, so the async refresh
/// path runs it on a blocking thread (audit 2 Tier 3 #3).
fn persist_to_disk(
    cache_path: &std::path::Path,
    etag: Option<String>,
    fetched_at: SystemTime,
    body: &[u8],
) -> Result<(), ClientError> {
    let file = CacheFile {
        etag,
        fetched_at_secs: fetched_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        index: serde_json::from_slice(body)?,
    };
    // `write_atomic` writes `<path>.tmp` beside the target, so the parent must
    // exist. Creating it here (on the blocking thread) instead of eagerly in the
    // sync `from_env` constructor keeps that I/O off the async path too (Tier 3 #3).
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    super_engine_spec::fs::write_atomic(cache_path, &serde_json::to_vec(&file)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super_engine_spec::test_product::IndexModel;
    use tempfile::tempdir;

    const DAEMON: Daemon = Daemon {
        product: &super_engine_protocol::SUPER_STT,
        version: "0.2.0",
        user_agent: "super-engine-daemon-tests",
    };

    fn client(url: impl Into<String>, cache_path: PathBuf) -> Client<IndexModel> {
        Client::new(DAEMON, url, cache_path, DEFAULT_TTL)
    }

    fn fixture_index() -> &'static str {
        r#"{"schema_version":1,"generated_at":"now","min_client":"0.0.0","backends":[]}"#
    }

    #[tokio::test]
    async fn fetches_and_caches() {
        super_engine_forge::install_crypto_provider();
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/idx.json")
            .with_status(200)
            .with_header("etag", "\"abc\"")
            .with_body(fixture_index())
            .create_async()
            .await;
        let dir = tempdir().unwrap();
        let c = client(format!("{}/idx.json", s.url()), dir.path().join("c.json"));
        let idx = c.refresh().await.unwrap();
        assert_eq!(idx.schema_version, 1);
        assert!(dir.path().join("c.json").exists());
    }

    #[tokio::test]
    async fn unsolicited_304_without_cache_is_unavailable_not_panic() {
        // A misbehaving proxy can answer 304 even though we sent no
        // If-None-Match (fresh client, no disk cache). Must surface as
        // Unavailable, not panic on an empty in-memory cache.
        super_engine_forge::install_crypto_provider();
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/idx.json")
            .with_status(304)
            .create_async()
            .await;
        let dir = tempdir().unwrap();
        let c = client(format!("{}/idx.json", s.url()), dir.path().join("c.json"));
        assert!(matches!(c.refresh().await, Err(ClientError::Unavailable)));
    }

    #[tokio::test]
    async fn returns_cache_when_network_fails() {
        super_engine_forge::install_crypto_provider();
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("c.json");
        std::fs::write(
            &cache_path,
            format!(
                r#"{{"etag":null,"fetched_at_secs":0,"index":{}}}"#,
                fixture_index()
            ),
        )
        .unwrap();
        let c = client("http://127.0.0.1:1/never", cache_path);
        let idx = c.get().await.unwrap();
        assert_eq!(idx.schema_version, 1);
    }
}
