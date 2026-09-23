// SPDX-License-Identifier: GPL-3.0-only
//! A product for this crate's own tests.
//!
//! Modeled on Super STT's contract, because that one exercises every rule the
//! crate enforces: two generations, fields the second one adds, a field it
//! makes required, and product keys in both `[capabilities]` and
//! `[[models]]`. Compiled only for tests (the `test-product` feature is how the
//! integration tests reach it).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::manifest::{ContractField, FieldRule, ModelEntry};
use crate::product::{Generation, Product, SchemaNames, generation_from_str};

/// The product the tests parse manifests for.
#[derive(Debug, Clone, Copy)]
pub enum TestProduct {}

/// The test product's contract generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Contract {
    /// The first generation.
    V1,
    /// v1 plus `[[models]].role` and `[[models]].force_preview_support`, and
    /// `[backend].id` becomes required.
    V2,
}

impl Generation for Contract {
    const ALL: &'static [Self] = &[Self::V1, Self::V2];
    const LATEST: Self = Self::V2;

    fn min_client(self) -> &'static str {
        match self {
            Self::V1 => "0.2.0",
            Self::V2 => "0.2.4-beta.1",
        }
    }
}

impl fmt::Display for Contract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
        }
    }
}

impl std::str::FromStr for Contract {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        generation_from_str(s)
    }
}

impl<'de> Deserialize<'de> for Contract {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The test product's `[capabilities]` keys.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Capabilities {
    /// A product capability, to show one flattens beside `websocket`.
    #[serde(default)]
    pub context: bool,
}

/// The test product's `[[models]]` keys.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Model {
    /// A v2 field.
    #[serde(default)]
    pub force_preview_support: bool,
    /// A v2 field with a value set of its own.
    #[serde(default)]
    pub role: Role,
}

/// What a test model is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The default.
    #[default]
    Transcription,
    /// The other role.
    PostProcessor,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transcription => write!(f, "transcription"),
            Self::PostProcessor => write!(f, "post_processor"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "transcription" => Ok(Self::Transcription),
            "post_processor" => Ok(Self::PostProcessor),
            _ => Err(format!("Unknown model role: {s}")),
        }
    }
}

impl Role {
    /// Whether this is the post-processing role.
    #[must_use]
    pub fn is_post_processor(self) -> bool {
        matches!(self, Self::PostProcessor)
    }
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The test product's index fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IndexModel {
    /// The model's role, read as the default when an index omits it.
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    Role::default().to_string()
}

impl Product for TestProduct {
    type Contract = Contract;
    type Capabilities = Capabilities;
    type Model = Model;
    type IndexModel = IndexModel;

    const CONTRACT_FIELDS: &'static [ContractField<Contract>] = &[
        ContractField {
            since: Contract::V2,
            rule: FieldRule::Added,
            table: "models",
            key: "role",
        },
        ContractField {
            since: Contract::V2,
            rule: FieldRule::Added,
            table: "models",
            key: "force_preview_support",
        },
        ContractField {
            since: Contract::V2,
            rule: FieldRule::RequiredFrom,
            table: "backend",
            key: "id",
        },
    ];

    const SCHEMA: SchemaNames = SchemaNames {
        backend_id: "https://example.com/test/backend.schema.json",
        backend_title: "Test backend manifest (backend.toml)",
        registry_id: "https://example.com/test/registry.schema.json",
        registry_title: "Test backend registry",
    };

    fn index_model(model: &ModelEntry<Model>) -> IndexModel {
        IndexModel {
            role: model.product.role.to_string(),
        }
    }
}
