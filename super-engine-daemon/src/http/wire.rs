// SPDX-License-Identifier: GPL-3.0-only
//! The auth-failure envelope, as a daemon documents it.
//!
//! The guards build these bodies with
//! [`error_response`](super::responses::error_response); the types exist so
//! the `OpenAPI` document can describe them.

use serde::Serialize;

/// The auth-failure envelope: `error_code` names the failure and
/// `data.reason` says which of its cases occurred.
///
/// Distinct from `ErrorEnvelope` because clients read `data.reason` here. The
/// identifier is in `message` too, where clients older than `error_code`
/// look for it.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ReasonEnvelope {
    /// Always `error`.
    #[schema(example = "error")]
    pub status: &'static str,
    /// The failure identifier, e.g. `invalid_session` or `auth_denied`.
    pub error_code: String,
    /// The same identifier, for clients that switched on it before
    /// `error_code` existed.
    pub message: String,
    pub data: Reason,
}

/// The `data` object of a [`ReasonEnvelope`].
#[derive(Serialize, utoipa::ToSchema)]
pub struct Reason {
    /// Which case of `message` occurred — e.g. `expired`, `exe_changed`,
    /// `user_denied`.
    pub reason: String,
}
