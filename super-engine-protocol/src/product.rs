// SPDX-License-Identifier: GPL-3.0-only
//! Which product a daemon or client is, and the names that follow from it.
//!
//! Everything a daemon and its clients must agree on to find each other is
//! named after the product: the directories under each XDG base, the socket,
//! the keyring service the session tokens live in, the environment variables
//! that override them, the scopes a token can carry and the event topics a
//! client can subscribe to. [`ProductSpec`] holds those names once, and the
//! functions in this crate and in `super-engine-client` take one instead of
//! assuming any product.
//!
//! Each product defines its own `ProductSpec`, in its own crate; nothing here
//! names one.

/// A product's names.
#[derive(Debug, PartialEq, Eq)]
pub struct ProductSpec {
    /// The name people see.
    pub display_name: &'static str,
    /// Names the product's directories and files: the directory under each
    /// XDG base, the `<slug>-http.sock` socket and the `<slug>-session`
    /// keyring service.
    pub slug: &'static str,
    /// The short name: the runtime subdirectory the socket lives in, and the
    /// host name every request carries (`<short name>.local`).
    pub short_name: &'static str,
    /// Prefix of the product's environment variables.
    pub env_prefix: &'static str,
    /// The loopback TCP port the daemon serves browsers on. Ports 7300–7309
    /// are the block reserved for the Super family, one per daemon.
    pub tcp_port: u16,
    /// Where the product's releases are published, as
    /// `<host>/<owner>/<repo>`: what the daemon checks for updates and the
    /// installer downloads from.
    pub repo: &'static str,
    /// The registry index the daemon lists and installs backends from, as
    /// the product's indexer publishes it.
    pub index_url: &'static str,
    /// The scopes this product adds to [`CORE_SCOPES`](crate::scopes::CORE_SCOPES).
    pub scopes: &'static [&'static str],
    /// The event topics this product adds to
    /// [`CORE_TOPICS`](crate::scopes::CORE_TOPICS), each with the scope a
    /// subscriber needs for it.
    pub topics: &'static [(&'static str, &'static str)],
}

impl ProductSpec {
    /// The product's environment variable `name`: `<PREFIX>_HTTP_SOCKET` for
    /// `HTTP_SOCKET`.
    #[must_use]
    pub fn env(&self, name: &str) -> String {
        format!("{}_{name}", self.env_prefix)
    }

    /// The file name of the daemon's HTTP socket, `<slug>-http.sock`.
    #[must_use]
    pub fn socket_file(&self) -> String {
        format!("{}-http.sock", self.slug)
    }

    /// The keyring service clients store their session tokens under,
    /// `<slug>-session`.
    #[must_use]
    pub fn session_keyring_service(&self) -> String {
        format!("{}-session", self.slug)
    }

    /// The host name every request to the daemon carries,
    /// `<short name>.local`.
    #[must_use]
    pub fn http_host(&self) -> String {
        format!("{}.local", self.short_name)
    }

    /// The file name of the helper that shows the consent dialog on Linux,
    /// `<slug>-consent`. The daemon runs it only from its own
    /// directory. [`consent`](crate::consent) is what the two say to each
    /// other.
    #[must_use]
    pub fn consent_helper(&self) -> String {
        format!("{}-consent", self.slug)
    }

    /// The file name of the daemon's binary, `<slug>-daemon`: how a daemon
    /// tells a live peer's backends from a dead one's.
    #[must_use]
    pub fn daemon_binary(&self) -> String {
        format!("{}-daemon", self.slug)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_product::TEST;

    /// Every name a daemon and its clients meet on follows from the spec:
    /// the socket, the keyring entry, the host header, the override
    /// variables, the consent helper and the daemon itself.
    #[test]
    fn the_names_follow_from_the_spec() {
        assert_eq!(TEST.socket_file(), "super-test-http.sock");
        assert_eq!(TEST.session_keyring_service(), "super-test-session");
        assert_eq!(TEST.http_host(), "test.local");
        assert_eq!(TEST.env("HTTP_SOCKET"), "SUPER_TEST_HTTP_SOCKET");
        assert_eq!(TEST.consent_helper(), "super-test-consent");
        assert_eq!(TEST.daemon_binary(), "super-test-daemon");
    }
}
