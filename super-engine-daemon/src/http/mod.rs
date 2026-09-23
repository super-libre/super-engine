// SPDX-License-Identifier: GPL-3.0-only
//! The HTTP transport around a daemon's router: the listeners it serves on,
//! what it knows about each caller, and the error bodies the guards answer
//! with.

pub mod origins;
pub mod peer;
pub mod responses;
pub mod server;
pub mod wire;

pub use peer::PeerInfo;
