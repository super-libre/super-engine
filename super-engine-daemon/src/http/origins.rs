// SPDX-License-Identifier: GPL-3.0-only
//! Which browser origins the TCP listener admits.
//!
//! The list is the user's `[http.tcp].allowed_origins`. Admitting an origin is
//! permission to *ask*, not permission to act: a page still faces the consent
//! dialog, and the token it gets is bound to its own origin and useless to any
//! other.

/// The wildcard entry for an allowlist, spelled as CORS spells it.
pub const ANY_ORIGIN: &str = "*";

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
pub fn is_origin_allowed(allowed: &[String], origin: &str) -> bool {
    allowed.iter().any(|a| a == ANY_ORIGIN || a == origin)
}

/// Whether the list admits every origin.
#[must_use]
pub fn admits_any_origin(allowed: &[String]) -> bool {
    allowed.iter().any(|a| a == ANY_ORIGIN)
}

#[cfg(test)]
mod tests {
    use super::{ANY_ORIGIN, admits_any_origin, is_origin_allowed};

    fn list(origins: &[&str]) -> Vec<String> {
        origins.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn the_wildcard_admits_every_origin() {
        let allowed = list(&[ANY_ORIGIN]);
        assert!(is_origin_allowed(&allowed, "https://example.test"));
        assert!(admits_any_origin(&allowed));
    }

    /// An exact match, not a prefix: a lookalike host that merely starts with
    /// an allowed origin must not get in.
    #[test]
    fn a_listed_origin_is_matched_exactly() {
        let allowed = list(&["http://127.0.0.1:8910"]);
        assert!(is_origin_allowed(&allowed, "http://127.0.0.1:8910"));
        assert!(!is_origin_allowed(
            &allowed,
            "http://127.0.0.1:8910.evil.test"
        ));
        assert!(!is_origin_allowed(&allowed, "http://127.0.0.1:8911"));
        assert!(!admits_any_origin(&allowed));
    }

    #[test]
    fn an_empty_list_admits_nothing() {
        assert!(!is_origin_allowed(&[], "http://127.0.0.1:8910"));
    }
}
