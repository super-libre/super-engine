// SPDX-License-Identifier: GPL-3.0-only
//! The auth scope catalog and the event topics each scope covers, shared so
//! the daemon (which validates `/auth/request` and `/events`), the consent
//! dialog (which describes each scope to the user) and the clients (which
//! decide what to ask for) can't drift. When they drift, a scope the daemon
//! accepts but the consent binary doesn't recognize renders the "unknown
//! scope — deny is safe" warning on a legitimate prompt, teaching users to
//! distrust real requests.
//!
//! The catalog is [`CORE_SCOPES`] plus the product's own
//! ([`ProductSpec::scopes`]), and the topics are [`CORE_TOPICS`] plus the
//! product's own ([`ProductSpec::topics`]). Both mirror the scope and topic
//! tables in each product's `docs/protocol`.

use crate::product::ProductSpec;

/// The scopes every product's daemon understands, in wire (`snake_case`)
/// form.
pub const CORE_SCOPES: &[&str] = &[
    "settings",
    "secrets",
    "status",
    "audio_visualization",
    "daemon_status",
];

/// The event topics every product's daemon publishes, each with the scope a
/// subscriber needs for it.
pub const CORE_TOPICS: &[(&str, &str)] = &[
    ("frequency_bands", "audio_visualization"),
    ("daemon_status_changed", "daemon_status"),
    ("download_progress", "daemon_status"),
    ("registry_install", "daemon_status"),
];

/// Every scope `product`'s daemon understands. A token may be granted any
/// non-empty subset. Source of truth for `/auth/request` validation and the
/// consent dialog.
pub fn known_scopes(product: &ProductSpec) -> impl Iterator<Item = &'static str> {
    CORE_SCOPES.iter().chain(product.scopes).copied()
}

/// True if `s` is a scope `product`'s daemon recognizes.
#[must_use]
pub fn is_known_scope(product: &ProductSpec, s: &str) -> bool {
    known_scopes(product).any(|known| known == s)
}

/// The scope a subscriber needs for `product`'s event `topic`, or `None` for
/// a topic that product does not publish. Mirrors the daemon's
/// `Topic::required_scope`, which a daemon-side test pins to this.
#[must_use]
pub fn required_scope_for_topic(product: &ProductSpec, topic: &str) -> Option<&'static str> {
    CORE_TOPICS
        .iter()
        .chain(product.topics)
        .find(|(name, _)| *name == topic)
        .map(|(_, scope)| *scope)
}

/// The first topic in `topics` that `scopes` does not grant (or whose name
/// `product` does not publish), or `None` when every topic is covered. `None`
/// means the daemon will not refuse the subscription with `403 scope_denied`
/// for a missing-scope reason. Clients assert this in their tests so a topic
/// added without its scope fails CI rather than silently 403-ing the whole
/// stream at runtime.
#[must_use]
pub fn uncovered_topic<'t>(
    product: &ProductSpec,
    scopes: &[&str],
    topics: &[&'t str],
) -> Option<&'t str> {
    topics
        .iter()
        .copied()
        .find(|t| match required_scope_for_topic(product, t) {
            Some(required) => !scopes.contains(&required),
            None => true,
        })
}

#[cfg(test)]
mod tests {
    use super::{CORE_TOPICS, is_known_scope, known_scopes, required_scope_for_topic};
    use crate::test_product::{OTHER, TEST};

    #[test]
    fn known_scopes_are_recognized() {
        for product in [&TEST, &OTHER] {
            for s in known_scopes(product) {
                assert!(is_known_scope(product, s), "{s} should be a known scope");
            }
            assert!(
                is_known_scope(product, "secrets"),
                "secrets must be an accepted scope"
            );
        }
    }

    #[test]
    fn old_personas_and_garbage_are_rejected() {
        for s in ["client", "widget", "", "Settings", "test ", "global"] {
            assert!(!is_known_scope(&TEST, s), "{s:?} must not be a known scope");
        }
    }

    /// Each product's scopes are its own: a token for one product's scope is
    /// good for nothing on another's daemon.
    #[test]
    fn a_product_scope_is_not_known_to_the_other_product() {
        assert!(is_known_scope(&TEST, "test"));
        assert!(!is_known_scope(&OTHER, "test"));
        assert!(is_known_scope(&OTHER, "other"));
        assert!(!is_known_scope(&TEST, "other"));
    }

    /// Every core topic names a core scope, so any product's daemon
    /// understands it; otherwise no token could ever subscribe.
    #[test]
    fn every_core_topic_needs_a_known_scope() {
        for (topic, scope) in CORE_TOPICS {
            assert!(
                is_known_scope(&TEST, scope),
                "{topic} needs {scope}, which is not a known scope"
            );
        }
    }

    #[test]
    fn topics_resolve_to_their_scopes() {
        assert_eq!(
            required_scope_for_topic(&TEST, "frequency_bands"),
            Some("audio_visualization")
        );
        assert_eq!(
            required_scope_for_topic(&TEST, "test_started"),
            Some("test_events")
        );
        assert_eq!(
            required_scope_for_topic(&OTHER, "other_started"),
            Some("other_events")
        );
        assert_eq!(required_scope_for_topic(&OTHER, "test_started"), None);
        assert_eq!(required_scope_for_topic(&TEST, "nope"), None);
    }
}
