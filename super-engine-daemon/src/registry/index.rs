// SPDX-License-Identifier: GPL-3.0-only
//! Daemon-side registry-index policy over `super_engine_spec::index`: the
//! `min_client` soft-floor check and the unsafe-path backend filter, as free
//! functions over [`Index`], the same pattern `validate_runtime` uses for
//! `Manifest`.

use semver::Version;
use super_engine_protocol::ProductSpec;
use super_engine_spec::index::Index;

/// Outcome of checking the running client against an index's `min_client`
/// soft floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinClientStatus {
    /// The client meets the floor, or the comparison cannot be made (an absent
    /// or unparseable `min_client`, or an unparseable client version). A
    /// malformed floor must never take the registry offline.
    Compatible,
    /// The client is older than the index's declared minimum. The registry
    /// stays usable; the user should be warned to update.
    TooOld { client: String, min_client: String },
}

/// Compare a client version against an index's `min_client` soft floor using
/// standard semver precedence. A missing or unparseable `min_client`, or an
/// unparseable `client_version`, yields [`MinClientStatus::Compatible`] — a bad
/// version string must not disable the registry.
#[must_use]
pub fn check_min_client(client_version: &str, min_client: &str) -> MinClientStatus {
    let (Ok(client), Ok(min)) = (Version::parse(client_version), Version::parse(min_client)) else {
        return MinClientStatus::Compatible;
    };
    if client < min {
        MinClientStatus::TooOld {
            client: client_version.to_owned(),
            min_client: min_client.to_owned(),
        }
    } else {
        MinClientStatus::Compatible
    }
}

/// Warn when this index's `min_client` floor is newer than the running
/// daemon, `product` at `current_version`. The registry stays usable —
/// `min_client` is a soft floor.
pub fn warn_if_client_too_old<M>(index: &Index<M>, product: &ProductSpec, current_version: &str) {
    if let MinClientStatus::TooOld { client, min_client } =
        check_min_client(current_version, &index.min_client)
    {
        log::warn!(
            "registry index requires client >= {min_client}, but this daemon is \
             {client}; newer backends may fail to install or run — please update {}",
            product.display_name
        );
    }
}

/// Sanitize backends fetched from `index.json` before anything downstream
/// (in particular [`super::install_dir_name`]) can join them onto the
/// backends directory. These values become directory names / are joined onto
/// the backends dir at install time; an absolute or traversing value would
/// escape it. A well-formed index (the indexer rejects them) never contains
/// such values, so a stray one — e.g. from a poisoned `<PREFIX>_REGISTRY_URL`
/// — is sanitized here rather than failing the whole index.
///
/// Every registry entry must carry a valid `backend_id`: the registry requires
/// an `id`, and it names the directory the backend installs into. An entry
/// without one, or with one that breaks the format, is dropped like an entry
/// with an unsafe `id` or `entrypoint`, rather than installed under its
/// registry key. A well-formed index has none; an index built before the
/// requirement, or a poisoned one, might.
///
/// `backend_id` is held to the full `[backend].id` format rule
/// ([`super_engine_spec::backend_id::is_valid`]) rather than to
/// `is_safe_component`. Every other route into an install directory name goes
/// through `Manifest::parse`, which enforces exactly that rule, so a looser
/// check here would make `index.json` the one input the daemon accepts below
/// its own contract. `.staging` shows why that matters: it is a legal path
/// component, so a component-level check passes it, but it names the shared
/// staging root every install stages through.
pub fn retain_safe_backends<M>(index: &mut Index<M>) {
    use super_engine_spec::{is_safe_component, is_safe_relative_path};
    index.backends.retain(|b| {
        if !b
            .backend_id
            .as_deref()
            .is_some_and(super_engine_spec::backend_id::is_valid)
        {
            log::warn!(
                "registry: dropping backend `{}` with a missing or malformed backend_id {:?}",
                b.id,
                b.backend_id
            );
            return false;
        }
        let ok = is_safe_component(&b.id) && is_safe_relative_path(&b.entrypoint);
        if !ok {
            log::warn!(
                "registry: dropping backend `{}` with unsafe id/entrypoint (entrypoint={:?})",
                b.id,
                b.entrypoint
            );
        }
        ok
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use super_engine_spec::index::{IndexAssets, IndexBackend};
    use super_engine_spec::test_product::IndexModel;

    type Index = super_engine_spec::index::Index<IndexModel>;

    /// A minimal-but-safe backend entry, for exercising `retain_safe_backends`
    /// without constructing the full field list every time.
    fn safe_backend(id: &str, backend_id: Option<&str>) -> IndexBackend<IndexModel> {
        IndexBackend {
            id: id.into(),
            backend_id: backend_id.map(String::from),
            source: "github.com/x/y".into(),
            version: "1.0.0".into(),
            tag: "v1.0.0".into(),
            name: "X".into(),
            description: None,
            license: String::new(),
            kind: "subprocess".into(),
            contract: "v1".into(),
            min_client: None,
            entrypoint: "x".into(),
            allowed_hosts: vec![],
            online: false,
            supports_gpu: false,
            supports_cpu: true,
            models: vec![],
            secrets: vec![],
            options: vec![],
            assets: IndexAssets::default(),
            index_stale: None,
            manifest: None,
        }
    }

    #[test]
    fn client_at_or_above_floor_is_compatible() {
        for (client, floor) in [
            ("0.1.0", "0.1.0"),        // exact floor is allowed (>=)
            ("0.2.0", "0.1.0"),        // newer minor
            ("1.0.0", "0.1.0"),        // newer major
            ("0.1.4-beta.2", "0.1.0"), // current beta: 0.1.4 core > 0.1.0
        ] {
            assert_eq!(
                check_min_client(client, floor),
                MinClientStatus::Compatible,
                "{client} should meet floor {floor}"
            );
        }
    }

    #[test]
    fn client_below_floor_is_too_old() {
        assert_eq!(
            check_min_client("0.0.9", "0.1.0"),
            MinClientStatus::TooOld {
                client: "0.0.9".into(),
                min_client: "0.1.0".into(),
            }
        );
        // Standard semver: a prerelease of the floor ranks below the release.
        assert!(matches!(
            check_min_client("0.1.0-rc.1", "0.1.0"),
            MinClientStatus::TooOld { .. }
        ));
    }

    #[test]
    fn malformed_versions_never_block_the_registry() {
        // A bad floor or client version must degrade to Compatible, not take
        // the whole registry offline.
        for (client, floor) in [
            ("0.1.4-beta.2", "not-a-version"),
            ("0.1.4-beta.2", ""),
            ("garbage", "0.1.0"),
        ] {
            assert_eq!(
                check_min_client(client, floor),
                MinClientStatus::Compatible,
                "{client:?} vs {floor:?} must not block"
            );
        }
    }

    /// `backend_id` arrives over the network via `index.json`. An unsafe value
    /// (here, path traversal) must not reach the install pipeline, and with no
    /// fallback to install under, the entry goes with it.
    #[test]
    fn retain_safe_backends_drops_an_entry_with_an_unsafe_backend_id() {
        let mut index = Index {
            schema_version: 1,
            generated_at: "now".into(),
            min_client: "0.1.0".into(),
            backends: vec![safe_backend("example", Some("../../../../home/jorge/.ssh"))],
        };
        retain_safe_backends(&mut index);
        assert!(index.backends.is_empty());
    }

    /// The registry requires an `id` of every entry, so an entry without a
    /// `backend_id` is not installed under its registry key: it is dropped.
    #[test]
    fn retain_safe_backends_drops_an_entry_without_a_backend_id() {
        let mut index = Index {
            schema_version: 1,
            generated_at: "now".into(),
            min_client: "0.1.0".into(),
            backends: vec![
                safe_backend("old", None),
                safe_backend("new", Some("com.example.new")),
            ],
        };
        retain_safe_backends(&mut index);
        assert_eq!(index.backends.len(), 1);
        assert_eq!(index.backends[0].id, "new");
    }

    /// `.staging` passes a component-level safety check but names the shared
    /// staging root every install stages through, so an index that published
    /// it would resolve an install directory onto that root. The boundary
    /// holds `backend_id` to the `[backend].id` format rule, which rejects
    /// it, and the entry with it.
    #[test]
    fn retain_safe_backends_drops_the_shared_staging_root_as_a_backend_id() {
        assert!(
            super_engine_spec::is_safe_component(".staging"),
            "the premise: a component-level check accepts .staging"
        );
        let mut index = Index {
            schema_version: 1,
            generated_at: "now".into(),
            min_client: "0.1.0".into(),
            backends: vec![safe_backend("example", Some(".staging"))],
        };
        retain_safe_backends(&mut index);
        assert!(
            index.backends.is_empty(),
            ".staging must never reach the install pipeline as a directory name"
        );
    }

    /// Every other route into an install directory name goes through
    /// `Manifest::parse`, which enforces the `[backend].id` format. This
    /// boundary must not be more lenient than the daemon's own contract.
    #[test]
    fn retain_safe_backends_drops_an_entry_with_a_malformed_backend_id() {
        for malformed in ["example", "com.backend", "com.example_x.backend", "APP.X.Y"] {
            let mut index = Index {
                schema_version: 1,
                generated_at: "now".into(),
                min_client: "0.1.0".into(),
                backends: vec![safe_backend("example", Some(malformed))],
            };
            retain_safe_backends(&mut index);
            assert!(
                index.backends.is_empty(),
                "an entry with malformed backend_id {malformed:?} must be dropped"
            );
        }
    }

    #[test]
    fn retain_safe_backends_keeps_a_safe_backend_id() {
        let mut index = Index {
            schema_version: 1,
            generated_at: "now".into(),
            min_client: "0.1.0".into(),
            backends: vec![safe_backend("example", Some("com.example.backend"))],
        };
        retain_safe_backends(&mut index);
        assert_eq!(
            index.backends[0].backend_id.as_deref(),
            Some("com.example.backend")
        );
    }

    /// An unsafe `id` or `entrypoint` drops the whole entry, however good its
    /// `backend_id`.
    #[test]
    fn retain_safe_backends_still_drops_an_entry_with_an_unsafe_id() {
        let mut index = Index {
            schema_version: 1,
            generated_at: "now".into(),
            min_client: "0.1.0".into(),
            backends: vec![safe_backend("../evil", Some("com.example.evil"))],
        };
        retain_safe_backends(&mut index);
        assert!(index.backends.is_empty());
    }

    #[test]
    fn index_warns_only_when_too_old() {
        // A wildly-high floor is too old; the published floor is fine. The
        // function logs as a side effect; we assert the underlying status it
        // acts on.
        let mk = |min_client: &str| Index {
            schema_version: 1,
            generated_at: "now".into(),
            min_client: min_client.into(),
            backends: vec![],
        };
        let product = &super_engine_protocol::test_product::TEST;
        warn_if_client_too_old(&mk("9999.0.0"), product, "0.2.0"); // the warn branch
        warn_if_client_too_old(&mk("0.1.0"), product, "0.2.0"); // the quiet branch
        assert!(matches!(
            check_min_client("0.2.0", "9999.0.0"),
            MinClientStatus::TooOld { .. }
        ));
        assert_eq!(
            check_min_client("0.2.0", "0.1.0"),
            MinClientStatus::Compatible
        );
    }
}
