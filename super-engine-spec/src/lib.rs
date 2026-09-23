// SPDX-License-Identifier: GPL-3.0-only
//! Canonical types for the backend contract every product shares: a
//! backend's `backend.toml` manifest, the maintainer-facing `registry.toml`,
//! and the `index.json` catalog built from them — and, in [`registry`], what
//! a daemon's `/registry` endpoints serve from that catalog.
//!
//! Each product plugs its own contract generations and fields in through
//! [`product::Product`].

pub mod arch;
pub mod backend_id;
pub mod entry;
pub mod forge;
pub mod fs;
pub mod index;
pub mod license;
pub mod manifest;
pub mod product;
pub mod registry;
mod safe_path;
#[cfg(feature = "schema")]
pub mod schema;
#[cfg(any(test, feature = "test-product"))]
pub mod test_product;
pub mod verify;
pub mod version;

pub use safe_path::{is_safe_component, is_safe_relative_path};
