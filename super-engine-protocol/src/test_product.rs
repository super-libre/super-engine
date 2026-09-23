// SPDX-License-Identifier: GPL-3.0-only
//! Two made-up products, for the tests here and in the crates built on this
//! one. Two, because some of what a daemon does is only right if it keeps
//! products apart: separate sockets, separate scopes, separate directories.

use crate::ProductSpec;

/// A product for tests.
pub static TEST: ProductSpec = ProductSpec {
    display_name: "Super Test",
    slug: "super-test",
    short_name: "test",
    env_prefix: "SUPER_TEST",
    tcp_port: 7308,
    repo: "github.com/example/super-test",
    index_url: "https://example.com/super-test/index.json",
    scopes: &["test", "test_events"],
    topics: &[("test_started", "test_events")],
};

/// A second product, to show two stay apart.
pub static OTHER: ProductSpec = ProductSpec {
    display_name: "Super Other",
    slug: "super-other",
    short_name: "other",
    env_prefix: "SUPER_OTHER",
    tcp_port: 7309,
    repo: "github.com/example/super-other",
    index_url: "https://example.com/super-other/index.json",
    scopes: &["other", "other_events"],
    topics: &[("other_started", "other_events")],
};
