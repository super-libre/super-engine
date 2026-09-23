// SPDX-License-Identifier: GPL-3.0-only
//! What a product adds to the backend contract.
//!
//! Super STT and Super TTS load backends the same way: one manifest format,
//! one registry, one set of transports. What differs is what a backend is
//! *for* — the contract generations each product has published, and the
//! fields a transcription model or a synthesis model declares on top of the
//! shared ones. A product names those differences by implementing [`Product`],
//! and every type in this crate that carries them is generic over it.
//!
//! The product's fields are flattened into the tables they extend, so a
//! `backend.toml` reads exactly as it did when each product parsed it with a
//! struct of its own.

use std::fmt;
use std::str::FromStr;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::manifest::{ContractField, Manifest, ManifestError, ModelEntry};

/// A product whose backends this crate describes.
///
/// Implemented on a marker type (an empty enum is enough); nothing is ever
/// constructed from it.
pub trait Product: Clone + fmt::Debug + Send + Sync + 'static {
    /// The contract generations this product's backends declare.
    type Contract: Generation;
    /// The `[capabilities]` keys this product adds beside `websocket`.
    type Capabilities: DeserializeOwned + Default + Clone + fmt::Debug + Send + Sync;
    /// The `[[models]]` keys this product adds beside the shared ones.
    type Model: DeserializeOwned + Clone + fmt::Debug + Send + Sync;
    /// The per-model fields this product's registry index carries beside
    /// `name` and `supported_devices`.
    type IndexModel: Serialize + DeserializeOwned + Clone + fmt::Debug + Send + Sync;

    /// Every field rule a generation after the first introduces. See
    /// [`ContractField`].
    const CONTRACT_FIELDS: &'static [ContractField<Self::Contract>];

    /// Names the generated JSON schemas publish under.
    const SCHEMA: SchemaNames;

    /// Rules a parsed manifest must meet beyond the shared ones, checked by
    /// [`Manifest::parse`] after everything else has passed.
    ///
    /// # Errors
    /// A [`ManifestError::Product`] naming the first rule the manifest breaks.
    fn validate(manifest: &Manifest<Self>) -> Result<(), ManifestError> {
        let _ = manifest;
        Ok(())
    }

    /// The index fields for one model, as the indexer and the daemon's
    /// install paths publish them.
    fn index_model(model: &ModelEntry<Self::Model>) -> Self::IndexModel;
}

/// A backend-protocol contract generation: the one thing a manifest declares
/// about what it implements.
///
/// A generation names a set of manifest fields and backend routes. Each
/// generation is additive over the one before, so a backend declares the
/// *lowest* generation whose fields it uses, and a daemon supports every
/// generation up to the one it was built with.
///
/// Implement it on a closed enum, on purpose. A daemon that predates a
/// generation cannot parse a manifest declaring it, which is what stops such
/// a daemon from installing a backend it cannot drive: the refusal needs no
/// field the old daemon would have to know about, because it is the *absence*
/// of knowledge that refuses. Every generation added therefore also gates
/// itself against every daemon released before it.
///
/// Route `FromStr` through [`generation_from_str`] and `Deserialize` through
/// `FromStr`, so [`ALL`](Self::ALL) plus `Display` is the only place a
/// generation is spelled, and so the error names what the build does know.
/// That message is what a user sees when a daemon meets a backend from a newer
/// generation, so it is worth more than serde's "unknown variant".
pub trait Generation:
    Copy
    + Ord
    + fmt::Debug
    + fmt::Display
    + FromStr<Err = String>
    + Serialize
    + DeserializeOwned
    + Send
    + Sync
    + 'static
{
    /// Every generation, oldest first. The derived `Ord` must agree.
    const ALL: &'static [Self];
    /// The newest generation this build understands. A manifest may not
    /// declare anything above it, because the closed enum refuses to parse it.
    const LATEST: Self;

    /// The product release that first understood this generation — the floor
    /// below which a daemon cannot install a backend declaring it.
    ///
    /// The indexer stamps this onto each index entry as `min_client`, so a
    /// daemon that does not know the generation can still tell the user what
    /// to update to. A backend author never writes a product version: they
    /// declare the contract, and this table is what it means.
    ///
    /// Reported, never compared: the daemon decides compatibility by whether
    /// it can parse the generation at all, so a prerelease of the version
    /// named here (`0.2.4-beta.1`, which semver orders *below* `0.2.4`) is not
    /// wrongly locked out. It is a string for the user, not a gate.
    fn min_client(self) -> &'static str;

    /// The generation immediately before this one; `None` for the first.
    #[must_use]
    fn previous(self) -> Option<Self> {
        Self::ALL
            .iter()
            .rev()
            .copied()
            .find(|candidate| *candidate < self)
    }
}

/// Parse a generation by its `Display` spelling.
///
/// # Errors
/// Names every generation this build knows when `s` is none of them.
pub fn generation_from_str<G: Generation>(s: &str) -> Result<G, String> {
    G::ALL
        .iter()
        .copied()
        .find(|g| g.to_string() == s)
        .ok_or_else(|| {
            let known: Vec<String> = G::ALL.iter().map(ToString::to_string).collect();
            format!(
                "unknown contract `{s}`; this build knows {}",
                known.join(", ")
            )
        })
}

/// Names the generated JSON schemas publish under.
#[derive(Debug, Clone, Copy)]
pub struct SchemaNames {
    /// `$id` of the `backend.toml` schema.
    pub backend_id: &'static str,
    /// `title` of the `backend.toml` schema.
    pub backend_title: &'static str,
    /// `$id` of the `registry.toml` schema.
    pub registry_id: &'static str,
    /// `title` of the `registry.toml` schema.
    pub registry_title: &'static str,
}
