// SPDX-License-Identifier: GPL-3.0-only
//! The vocabulary a daemon and its clients share: where the daemon's socket
//! and files live, which scopes a token can carry, how a sandboxed caller is
//! identified, and the wire types every client reads.

pub mod audio;
pub mod consent;
pub mod logging;
pub mod models;
pub mod paths;
pub mod product;
pub mod runtime;
pub mod sandbox;
pub mod scopes;
pub mod serde_helpers;

pub use audio::FrequencyData;
pub use product::{ProductSpec, SUPER_STT, SUPER_TTS};
