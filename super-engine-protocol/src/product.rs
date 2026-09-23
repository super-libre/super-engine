// SPDX-License-Identifier: GPL-3.0-only
//! Which product a daemon or client is, and the names that follow from it.
//!
//! Everything a daemon and its clients must agree on to find each other is
//! named after the product: the directories under each XDG base, the socket,
//! the keyring service the session tokens live in, the environment variables
//! that override them, the scopes a token can carry and the event topics a
//! client can subscribe to. [`ProductSpec`] holds those names once, and the
//! functions in this crate and in `super-engine-client` take one instead of
//! assuming Super STT.
//!
//! Both products are defined here rather than in their own repositories, so
//! a client that talks to either (the COSMIC applet shows both) needs nothing
//! from either product to find its daemon.

/// A product's names.
#[derive(Debug, PartialEq, Eq)]
pub struct ProductSpec {
    /// The name people see, e.g. `Super STT`.
    pub display_name: &'static str,
    /// Names the product's directories and files, e.g. `super-stt`: the
    /// directory under each XDG base, the `super-stt-http.sock` socket and the
    /// `super-stt-session` keyring service.
    pub slug: &'static str,
    /// The short name, e.g. `stt`: the runtime subdirectory the socket lives
    /// in, and the host name every request carries (`stt.local`).
    pub short_name: &'static str,
    /// Prefix of the product's environment variables, e.g. `SUPER_STT`.
    pub env_prefix: &'static str,
    /// The loopback TCP port the daemon serves browsers on. Ports 7300–7309
    /// are the block reserved for the Super family, one per daemon.
    pub tcp_port: u16,
    /// The scopes this product adds to [`CORE_SCOPES`](crate::scopes::CORE_SCOPES).
    pub scopes: &'static [&'static str],
    /// The event topics this product adds to
    /// [`CORE_TOPICS`](crate::scopes::CORE_TOPICS), each with the scope a
    /// subscriber needs for it.
    pub topics: &'static [(&'static str, &'static str)],
}

impl ProductSpec {
    /// The product's environment variable `name`, e.g. `SUPER_STT_HTTP_SOCKET`
    /// for `HTTP_SOCKET`.
    #[must_use]
    pub fn env(&self, name: &str) -> String {
        format!("{}_{name}", self.env_prefix)
    }

    /// The file name of the daemon's HTTP socket, e.g. `super-stt-http.sock`.
    #[must_use]
    pub fn socket_file(&self) -> String {
        format!("{}-http.sock", self.slug)
    }

    /// The keyring service clients store their session tokens under, e.g.
    /// `super-stt-session`.
    #[must_use]
    pub fn session_keyring_service(&self) -> String {
        format!("{}-session", self.slug)
    }

    /// The host name every request to the daemon carries, e.g. `stt.local`.
    #[must_use]
    pub fn http_host(&self) -> String {
        format!("{}.local", self.short_name)
    }

    /// The file name of the helper that shows the consent dialog on Linux,
    /// e.g. `super-stt-consent`. The daemon runs it only from its own
    /// directory. [`consent`](crate::consent) is what the two say to each
    /// other.
    #[must_use]
    pub fn consent_helper(&self) -> String {
        format!("{}-consent", self.slug)
    }
}

/// Super STT: speech to text.
pub static SUPER_STT: ProductSpec = ProductSpec {
    display_name: "Super STT",
    slug: "super-stt",
    short_name: "stt",
    env_prefix: "SUPER_STT",
    tcp_port: 7300,
    scopes: &["transcribe", "recording_events", "global_transcriptions"],
    topics: &[
        ("recording_started", "recording_events"),
        ("recording_stopped", "recording_events"),
        ("recording_state", "recording_events"),
        ("transcribing_started", "recording_events"),
        ("transcribing_stopped", "recording_events"),
        ("partial_stt", "global_transcriptions"),
        ("final_stt", "global_transcriptions"),
    ],
};

/// Super TTS: text to speech.
pub static SUPER_TTS: ProductSpec = ProductSpec {
    display_name: "Super TTS",
    slug: "super-tts",
    short_name: "tts",
    env_prefix: "SUPER_TTS",
    tcp_port: 7301,
    scopes: &["speak", "voices", "playback_events"],
    topics: &[
        ("speaking_state", "playback_events"),
        ("speech_progress", "playback_events"),
    ],
};

/// Every product this crate knows.
pub static PRODUCTS: [&ProductSpec; 2] = [&SUPER_STT, &SUPER_TTS];

#[cfg(test)]
mod tests {
    use super::{PRODUCTS, SUPER_STT, SUPER_TTS};

    /// The derived names are the ones each product shipped with before they
    /// shared this crate. A change here moves a socket, a keyring entry or an
    /// override variable out from under every installed client.
    #[test]
    fn derived_names_match_what_each_product_shipped() {
        assert_eq!(SUPER_STT.socket_file(), "super-stt-http.sock");
        assert_eq!(SUPER_STT.session_keyring_service(), "super-stt-session");
        assert_eq!(SUPER_STT.http_host(), "stt.local");
        assert_eq!(SUPER_STT.env("HTTP_SOCKET"), "SUPER_STT_HTTP_SOCKET");
        assert_eq!(SUPER_STT.consent_helper(), "super-stt-consent");

        assert_eq!(SUPER_TTS.socket_file(), "super-tts-http.sock");
        assert_eq!(SUPER_TTS.session_keyring_service(), "super-tts-session");
        assert_eq!(SUPER_TTS.http_host(), "tts.local");
        assert_eq!(SUPER_TTS.env("HTTP_SOCKET"), "SUPER_TTS_HTTP_SOCKET");
        assert_eq!(SUPER_TTS.consent_helper(), "super-tts-consent");
    }

    /// Two daemons may run side by side, so nothing either one binds, stores
    /// or reads may be named the same.
    #[test]
    fn no_two_products_share_a_name() {
        for (i, a) in PRODUCTS.iter().enumerate() {
            for b in &PRODUCTS[i + 1..] {
                assert_ne!(a.slug, b.slug);
                assert_ne!(a.short_name, b.short_name);
                assert_ne!(a.env_prefix, b.env_prefix);
                assert_ne!(a.tcp_port, b.tcp_port);
            }
        }
    }
}
