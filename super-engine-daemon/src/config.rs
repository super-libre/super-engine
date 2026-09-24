// SPDX-License-Identifier: GPL-3.0-only
//! The daemon's own settings file, `daemon.toml`, and the part of it every
//! daemon shares: the HTTP surface beyond the Unix socket.
//!
//! A product's `DaemonConfig` is its own struct; [`load`] and [`save`] read
//! and write it the way every daemon does, and [`ConfigFile::normalize`] is
//! where it repairs a stale value rather than resetting the whole file.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use super_engine_protocol::{ProductSpec, paths};

/// A daemon's settings, as [`load`] and [`save`] handle them.
pub trait ConfigFile: Serialize + DeserializeOwned + Default {
    /// Repair values that parsed but are no longer valid, such as a device
    /// name from an older vocabulary. Runs after every successful parse; a
    /// file that does not parse at all is reset to defaults instead.
    fn normalize(&mut self) {}
}

/// `daemon.toml` in the product's config directory.
#[must_use]
pub fn config_path(product: &ProductSpec) -> PathBuf {
    paths::config_dir(product).join("daemon.toml")
}

/// Parse `content`, falling back to defaults when it does not parse. Pure (no
/// I/O) so the load/reset decision is testable without a file. Returns the
/// config and whether it was reset, so the caller knows to write the defaults.
#[must_use]
pub fn parse_or_reset<C: ConfigFile>(content: &str) -> (C, bool) {
    match toml::from_str::<C>(content) {
        Ok(mut config) => {
            config.normalize();
            (config, false)
        }
        Err(e) => {
            log::warn!("Failed to parse config: {e}. Resetting to defaults.");
            (C::default(), true)
        }
    }
}

/// Load the config at `path`.
///
/// Falls back to defaults when the file is missing or cannot be parsed (e.g.
/// after a format change). When falling back, the default config is saved to
/// disk so subsequent loads succeed cleanly. If individual fields fell back to
/// their defaults (a stale enum value, or one [`ConfigFile::normalize`]
/// repaired), the canonical form is rewritten so the warning doesn't repeat
/// next startup.
#[must_use]
pub fn load<C: ConfigFile>(path: &Path) -> C {
    let Ok(content) = std::fs::read_to_string(path) else {
        return C::default();
    };

    let (config, was_reset) = parse_or_reset::<C>(&content);
    if was_reset {
        // Persist the regenerated defaults so subsequent loads are clean.
        if let Err(e) = save(path, &config) {
            log::error!("Failed to save default config after parse error: {e}");
        }
    } else if let Ok(canonical) = toml::to_string_pretty(&config)
        && canonical != content
        && let Err(e) = save(path, &config)
    {
        log::error!("Failed to rewrite config in canonical form: {e}");
    }
    config
}

/// Save `config` to `path`, creating its directory. Blocking
/// (`std::fs::write`); on the async runtime call it from `spawn_blocking`.
///
/// # Errors
///
/// Returns an error if the directory cannot be created, serialization fails,
/// or the file cannot be written.
pub fn save<C: ConfigFile>(path: &Path, config: &C) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, toml::to_string_pretty(config)?)?;
    log::debug!("Saved daemon config to {}", path.display());
    Ok(())
}

/// The daemon's HTTP surface beyond the Unix socket it always serves.
///
/// Contract: `docs/protocol/transport.md`. Every field is defaulted, so a
/// `daemon.toml` written before the section existed loads with the TCP
/// listener off — which is the only state in which the daemon's callers are
/// all peer-credential-verified.
///
/// `DEFAULT_PORT` is the product's `ProductSpec::tcp_port`: a const parameter
/// because it is the default a `daemon.toml` without a port loads with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HttpConfig<const DEFAULT_PORT: u16> {
    #[serde(default)]
    pub tcp: TcpConfig<DEFAULT_PORT>,
}

/// The loopback TCP listener, which is what a browser can reach.
///
/// A browser cannot dial a Unix socket, so a web client needs this. What it
/// costs is the identity model: `SO_PEERCRED` gives the Unix socket a caller
/// identity the kernel vouches for, and TCP has no equivalent. A TCP caller is
/// identified by its `Origin` header instead — asserted by the browser, not
/// proven.
///
/// **What guards the surface is therefore consent, not this config.** Any page
/// may *ask*; the dialog names the site and the user decides. That is the same
/// bargain the Unix socket strikes with a binary, one notch weaker because the
/// name comes from the browser rather than the kernel — which is what the
/// dialog says, in those words.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TcpConfig<const DEFAULT_PORT: u16> {
    /// Whether the daemon also serves the API on `127.0.0.1:{port}`.
    ///
    /// On by default, so a web client works without the user first finding a
    /// config file. A port that cannot be bound is logged and skipped rather
    /// than fatal: the Unix socket is the daemon's primary transport, and
    /// refusing to start because something else holds this port would take the
    /// whole daemon down for the sake of an extra.
    #[serde(default = "default_tcp_enabled")]
    pub enabled: bool,
    /// The loopback port to bind.
    ///
    /// Fixed rather than OS-chosen because it is half of a browser client's
    /// origin: a port that moved on every restart would invalidate the other
    /// side's bookmarks and its stored token binding. The number itself has no
    /// registered meaning. `DEFAULT_PORT` unless the config says otherwise.
    #[serde(default = "default_tcp_port::<DEFAULT_PORT>")]
    pub port: u16,
    /// The browser origins allowed to call the API, each a full origin such as
    /// `http://127.0.0.1:8910` — scheme, host and port, no trailing slash.
    /// [`ANY_ORIGIN`] anywhere in the list admits every origin, which is the
    /// default.
    ///
    /// Admitting an origin is permission to *ask*, not permission to act: a
    /// page still faces the consent dialog, and the token it gets is bound to
    /// its own origin and useless to any other. Narrowing this list is for
    /// deployments that want a page stopped before it can put a dialog on the
    /// user's screen at all.
    ///
    /// An empty list admits nothing — the deliberate lockdown, distinct from
    /// the default. Either way the daemon enforces this itself on every
    /// request rather than relying on the CORS headers it also sends: CORS is a
    /// browser-side courtesy that a non-browser client simply ignores, so it
    /// cannot be what guards the surface.
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

/// The wildcard entry for [`TcpConfig::allowed_origins`], spelled as CORS
/// spells it.
pub const ANY_ORIGIN: &str = "*";

/// See [`TcpConfig::enabled`].
fn default_tcp_enabled() -> bool {
    true
}

/// See [`TcpConfig::port`].
fn default_tcp_port<const PORT: u16>() -> u16 {
    PORT
}

/// See [`TcpConfig::allowed_origins`].
fn default_allowed_origins() -> Vec<String> {
    vec![ANY_ORIGIN.to_string()]
}

/// Written out rather than derived so a `TcpConfig::default()` and a config
/// deserialized from an absent `[http.tcp]` agree on every field. The derived
/// impl would answer `false`, `0` and `[]` — which is not merely a different
/// default but the opposite behaviour, since `0` means "let the OS choose" to
/// every bind call that saw it and `[]` admits nothing.
impl<const DEFAULT_PORT: u16> Default for TcpConfig<DEFAULT_PORT> {
    fn default() -> Self {
        Self {
            enabled: default_tcp_enabled(),
            port: DEFAULT_PORT,
            allowed_origins: default_allowed_origins(),
        }
    }
}

impl<const DEFAULT_PORT: u16> TcpConfig<DEFAULT_PORT> {
    /// The address to bind, or `None` when the listener is switched off.
    ///
    /// Always loopback: a listener reachable from the network would be a
    /// different product with a different threat model, and nothing in the
    /// consent flow is prepared for a caller on another host.
    #[must_use]
    pub fn bind_addr(&self) -> Option<std::net::SocketAddr> {
        self.enabled
            .then(|| std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, self.port)))
    }

    /// Whether `origin` is one the user has allowed.
    ///
    /// [`ANY_ORIGIN`] anywhere in the list admits everything. Otherwise this is
    /// an exact, case-sensitive match: origins are compared as the opaque
    /// strings browsers send rather than parsed and normalized, so there is no
    /// gap between what the user wrote down and what is accepted — a prefix or
    /// suffix match here would let `http://127.0.0.1:8910.evil.test` through.
    ///
    /// Note what this does *not* do: it never widens what a caller becomes. An
    /// admitted origin is still recorded as itself, so a wildcard list grants
    /// every page its own identity rather than a shared one.
    #[must_use]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|a| a == ANY_ORIGIN || a == origin)
    }

    /// Whether the list is the permissive default.
    ///
    /// Only used to phrase the startup log, so an operator can see which of the
    /// two the running daemon is doing without going to read the config.
    #[must_use]
    pub fn admits_any_origin(&self) -> bool {
        self.allowed_origins.iter().any(|a| a == ANY_ORIGIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The port a config without one loads with is the product's.
    #[test]
    fn an_absent_port_is_the_products_default() {
        let config: HttpConfig<7308> = toml::from_str("[tcp]\nenabled = true\n").unwrap();
        assert_eq!(config.tcp.port, 7308);
        assert_eq!(HttpConfig::<7308>::default().tcp.port, 7308);
        assert_eq!(
            config.tcp.bind_addr(),
            Some(std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                7308
            )))
        );
    }

    /// An absent section and a default config agree on every field, and the
    /// default admits every origin.
    #[test]
    fn an_absent_section_is_the_default() {
        let config: HttpConfig<7308> = toml::from_str("").unwrap();
        assert_eq!(config, HttpConfig::default());
        assert!(config.tcp.enabled);
        assert!(config.tcp.admits_any_origin());
        assert!(config.tcp.is_origin_allowed("http://127.0.0.1:8910"));
    }

    /// An explicit list is matched exactly, and an empty one admits nothing.
    #[test]
    fn origins_match_exactly() {
        let mut tcp = TcpConfig::<7308>::default();
        tcp.allowed_origins = vec!["http://127.0.0.1:8910".to_string()];
        assert!(tcp.is_origin_allowed("http://127.0.0.1:8910"));
        assert!(!tcp.is_origin_allowed("http://127.0.0.1:8910.evil.test"));
        tcp.allowed_origins.clear();
        assert!(!tcp.is_origin_allowed("http://127.0.0.1:8910"));
        tcp.enabled = false;
        assert_eq!(tcp.bind_addr(), None);
    }

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Settings {
        #[serde(default)]
        device: String,
    }

    impl ConfigFile for Settings {
        fn normalize(&mut self) {
            if self.device == "cuda" {
                self.device = "gpu".to_string();
            }
        }
    }

    /// A file that does not parse resets; one that does is normalized.
    #[test]
    fn parse_resets_or_normalizes() {
        let (settings, reset) = parse_or_reset::<Settings>("device = [");
        assert!(reset);
        assert_eq!(settings, Settings::default());
        let (settings, reset) = parse_or_reset::<Settings>("device = \"cuda\"\n");
        assert!(!reset);
        assert_eq!(settings.device, "gpu");
    }

    /// A load rewrites a repaired file in canonical form, and saves defaults
    /// over one that did not parse.
    #[test]
    fn load_rewrites_what_it_repaired() {
        let dir =
            std::env::temp_dir().join(format!("super-engine-config-test-{}", std::process::id()));
        let path = dir.join("daemon.toml");
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(&path, "device = \"cuda\"\n").unwrap();
        let settings: Settings = load(&path);
        assert_eq!(settings.device, "gpu");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "device = \"gpu\"\n"
        );

        std::fs::write(&path, "device = [").unwrap();
        let settings: Settings = load(&path);
        assert_eq!(settings, Settings::default());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "device = \"\"\n");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
