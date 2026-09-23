// SPDX-License-Identifier: GPL-3.0-only
//! What a daemon's `/registry` endpoints answer with: the index's backends as
//! this host sees them, and the install, update and refresh requests and
//! replies. All fields `snake_case`.
//!
//! The model entries carry the product's own fields, so the types that hold
//! them are generic. Each is generic over the whole type it holds — a
//! [`RegistryBackend`] over its model entry, a [`RegistryListResponse`] over
//! its backend — rather than over the product's fields: utoipa names a
//! schema after the type arguments written inside another schema, which
//! would publish `RegistryBackend` as `RegistryBackend_SttIndexModel`. A
//! product binds them once, with its [`RegistryModel`], and lists
//! `RegistryBackend` and `RegistryModel` among its `OpenAPI` components,
//! since a type reached only through a type parameter is not collected on
//! its own.

use serde::{Deserialize, Serialize};

pub mod events;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryListResponse<Backend> {
    pub schema_version: u32,
    pub generated_at: String,
    // The product's `RegistryBackend`s.
    pub backends: Vec<Backend>,
}

// A flat mirror of the registry listing's JSON. The lint wants related flags
// grouped into a sub-struct, which here would reshape the wire payload to suit
// an internal API guideline.
#[allow(clippy::struct_excessive_bools)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBackend<Model> {
    pub id: String,
    /// The backend's reverse-DNS identifier, or `None` when the registry entry
    /// predates it. Names the install directory.
    #[serde(default)]
    pub backend_id: Option<String>,
    pub source: String,
    pub version: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub license: String,
    pub kind: String,
    /// The contract generation the backend declares, as published. Carried
    /// as a string so a client lists an entry whose generation it does not
    /// know; `compatibility` says whether this daemon can drive it.
    pub contract: String,
    /// The release of the daemon's product that first understood `contract`,
    /// as stamped by the indexer. `None` for an index that predates the
    /// stamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_client: Option<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    pub online: bool,
    pub supports_gpu: bool,
    pub supports_cpu: bool,
    // The product's `RegistryModel`s.
    pub models: Vec<Model>,
    pub secrets: Vec<RegistrySecret>,
    pub options: Vec<RegistryOption>,
    pub compatibility: Compatibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    /// Whether `version` is newer than `installed_version`, decided by the
    /// daemon.
    ///
    /// The comparison is semver, and it belongs here rather than in each client
    /// for the same reason `installed_version` does: the daemon is what reads
    /// the installed manifest and owns the index, so it is the one place that
    /// can answer without a client re-deriving it. A client that wants to
    /// present the versions still has both.
    ///
    /// `false` when nothing is installed, when the installed version is at or
    /// ahead of the index's, or when either version does not parse.
    #[serde(default)]
    pub update_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_stale: Option<IndexStale>,
}

// The listing's model/secret/option leaves are field-identical to the
// `index.json` leaves, so they share one canonical definition rather than
// drifting. Re-exported under the historical `Registry*` names.
pub use crate::index::{
    IndexModel as RegistryModel, IndexOption as RegistryOption, IndexSecret as RegistrySecret,
};

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compatibility {
    pub compatible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_asset: Option<SelectedAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the block is "this daemon is too old" rather than "this
    /// machine cannot run it".
    ///
    /// The two are hidden differently. A host that lacks the right GPU will
    /// never run the asset, so Browse tucks it behind "Show incompatible"; a
    /// daemon one version behind is a thing the user can fix in a minute,
    /// and hiding it hides the only notice they would get. `false` on an older
    /// daemon that does not send the field, which lists as it always did.
    #[serde(default)]
    pub needs_client_update: bool,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedAsset {
    pub target: String,
    /// Acceleration backends the selected build carries. A single entry is
    /// both read and written as a bare string, a list of two or more as an
    /// array — a client that declares this field as a plain `String` still
    /// parses the catalog for every asset that carries one runtime.
    #[serde(
        deserialize_with = "crate::index::one_or_many_string",
        serialize_with = "crate::index::one_or_many_string_ser"
    )]
    pub accel: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cuda_major: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cuda_sm: Option<u32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cudnn: bool,
}

pub use crate::index::IndexStale;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InstallRequest {
    BySource {
        source: String,
    },
    ByRepoUrl {
        repo_url: String,
        /// Which forge API to speak. Optional: the daemon reads the host out
        /// of `repo_url` when it is absent, and only a host no adapter serves
        /// needs it spelled out.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        forge: Option<crate::forge::Forge>,
    },
    ByLocalPath {
        local_path: String,
    },
}

/// Answer to a preview request: what a source would install, in the same
/// shape a catalog listing uses, so a client renders it with whatever it
/// already renders Browse cards with.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewResponse<Backend> {
    // The product's `RegistryBackend`.
    pub backend: Backend,
    /// `unverified_source` for the custom-repo and local-import routes, as the
    /// install response carries it. `None` for a registry `source`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallAccepted {
    pub install_id: String,
    pub source: String,
    pub version: String,
    pub selected_asset: SelectedAsset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRequest {
    pub source: String,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_id: Option<String>,
    pub from_version: String,
    pub to_version: String,
    pub noop: bool,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshResponse {
    pub schema_version: u32,
    pub generated_at: String,
    pub backend_count: usize,
}

#[cfg(test)]
mod tests {
    use crate::test_product::IndexModel;

    type RegistryBackend = super::RegistryBackend<super::RegistryModel<IndexModel>>;

    /// The minimal registry listing entry every test below starts from,
    /// extending it with `serde_json::Value` indexing for the field each test
    /// cares about. One fixture rather than three keeps them from drifting
    /// apart on the fields that are merely required to parse at all.
    fn minimal_backend_json() -> serde_json::Value {
        serde_json::json!({
            "id": "openai",
            "source": "github.com/example/openai",
            "version": "0.1.1",
            "name": "OpenAI",
            "license": "Apache-2.0",
            "kind": "wasm",
            "contract": "v1",
            "online": true,
            "supports_gpu": false,
            "supports_cpu": false,
            "models": [],
            "secrets": [],
            "options": [],
            "compatibility": { "compatible": true },
        })
    }

    /// A daemon that predates `update_available` still deserializes here. The
    /// field moved the update decision from the client to the daemon; a client
    /// that hard-required it would fail to list anything at all against a
    /// daemon that has not rolled over, which is worse than not knowing about
    /// an update.
    #[test]
    fn a_registry_entry_without_update_available_still_parses() {
        let mut v = minimal_backend_json();
        v["installed_version"] = serde_json::json!("0.1.0");
        let b: RegistryBackend = serde_json::from_value(v).expect("older payload must parse");
        assert!(
            !b.update_available,
            "an absent flag reads as no update, never as one"
        );
    }

    /// Unknown keys are ignored, so a newer daemon adding a field does not
    /// break a client built against this shape. The compatibility runs both
    /// ways or it is not compatibility.
    #[test]
    fn a_registry_entry_with_an_unknown_field_still_parses() {
        let mut v = minimal_backend_json();
        v["update_available"] = serde_json::json!(true);
        v["a_field_from_a_later_daemon"] = serde_json::json!(42);
        let b: RegistryBackend = serde_json::from_value(v).expect("newer payload must parse");
        assert!(b.update_available);
    }

    /// A daemon that predates `backend_id` still deserializes here, and a
    /// response carrying one round-trips.
    #[test]
    fn backend_id_is_optional_on_the_wire() {
        let without: RegistryBackend =
            serde_json::from_value(minimal_backend_json()).expect("parses without backend_id");
        assert!(without.backend_id.is_none());

        let mut v = minimal_backend_json();
        v["backend_id"] = serde_json::json!("com.example.backend");
        let with: RegistryBackend = serde_json::from_value(v).expect("parses with backend_id");
        assert_eq!(with.backend_id.as_deref(), Some("com.example.backend"));
    }

    fn selected(accel: &[&str]) -> super::SelectedAsset {
        super::SelectedAsset {
            target: "x86_64-unknown-linux-gnu".into(),
            accel: accel.iter().map(|a| (*a).to_string()).collect(),
            cuda_major: Some(12),
            cuda_sm: Some(86),
            cudnn: false,
        }
    }

    /// An app built before the list form declares `accel` as a required
    /// `String` and fails to parse the *whole* registry listing
    /// when it turns into an array. Every asset carrying one runtime — which
    /// is every asset a backend can publish — therefore keeps the bare-string
    /// shape on the wire.
    #[test]
    fn a_single_accel_selection_still_serializes_as_a_bare_string() {
        let json = serde_json::to_string(&selected(&["cuda"])).expect("serializes");
        assert!(
            json.contains(r#""accel":"cuda""#),
            "accel is no longer a bare string; an older app cannot parse the catalog: {json}"
        );

        #[derive(serde::Deserialize)]
        struct DeployedSelectedAsset {
            accel: String,
        }
        let deployed: DeployedSelectedAsset =
            serde_json::from_str(&json).expect("an older app must still parse this");
        assert_eq!(deployed.accel, "cuda");
    }

    /// A build carrying two runtimes has no bare-string spelling, so it is
    /// written as the array it is, and read back unchanged.
    #[test]
    fn a_multi_accel_selection_serializes_as_an_array_and_round_trips() {
        let json = serde_json::to_string(&selected(&["cuda", "rocm"])).expect("serializes");
        assert!(
            json.contains(r#""accel":["cuda","rocm"]"#),
            "a multi-runtime build must keep its list: {json}"
        );
        let back: super::SelectedAsset = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back.accel, vec!["cuda".to_string(), "rocm".to_string()]);
    }

    /// Read leniency is unchanged: a payload written either way parses.
    #[test]
    fn a_selection_parses_from_either_shape() {
        let scalar: super::SelectedAsset =
            serde_json::from_str(r#"{"target":"t","accel":"cuda"}"#).expect("scalar parses");
        assert_eq!(scalar.accel, vec!["cuda".to_string()]);
        let list: super::SelectedAsset =
            serde_json::from_str(r#"{"target":"t","accel":["cuda"]}"#).expect("list parses");
        assert_eq!(list.accel, vec!["cuda".to_string()]);
    }
}
