// SPDX-License-Identifier: GPL-3.0-only
//! The auth-failure envelope, as a daemon documents it.
//!
//! The guards build these bodies with
//! [`error_response`](super::responses::error_response); the types exist so
//! the `OpenAPI` document can describe them.

use serde::Serialize;

/// The auth-failure envelope: `message` names the failure and `data.reason`
/// says which of its cases occurred.
///
/// Distinct from `ErrorEnvelope` because the auth surface predates
/// `error_code` and clients read `data.reason` there. Both are documented
/// rather than reconciled, since changing either is a breaking wire change.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ReasonEnvelope {
    /// Always `error`.
    #[schema(example = "error")]
    pub status: &'static str,
    /// The failure identifier, e.g. `invalid_session` or `auth_denied`.
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
