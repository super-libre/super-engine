// SPDX-License-Identifier: GPL-3.0-only
//! Event payloads streamed on `/events` for registry install progress.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RegistryEvent {
    #[serde(rename = "registry.install.progress")]
    Progress {
        install_id: String,
        source: String,
        phase: InstallPhase,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bytes_done: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bytes_total: Option<u64>,
    },
    #[serde(rename = "registry.install.completed")]
    Completed {
        install_id: String,
        source: String,
        version: String,
    },
    #[serde(rename = "registry.install.failed")]
    Failed {
        install_id: String,
        source: String,
        phase: InstallPhase,
        error: InstallError,
        /// What went wrong, in words, when the daemon knows more than `error`
        /// says: for `manifest_invalid`, the rule the manifest broke. Absent
        /// otherwise, and from a daemon that predates the field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    #[serde(rename = "registry.refresh.completed")]
    RefreshCompleted {
        generated_at: String,
        backend_count: usize,
    },
    #[serde(rename = "registry.refresh.failed")]
    RefreshFailed { error: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    Resolving,
    Downloading,
    Verifying,
    Extracting,
    Installing,
    Rescanning,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallError {
    Incompatible,
    DownloadFailed,
    AssetHashMismatch,
    TarballUnsafe,
    InstallIoError,
    /// The `backend.toml` manifest asset was absent or failed verification: no
    /// `manifest` pin on the entry, unparseable bytes, failed runtime
    /// validation, over the size cap, or an identity/entrypoint inconsistent
    /// with the index entry.
    ManifestInvalid,
    /// The directory this backend installs into already holds a *different*
    /// backend — one whose `backend.toml` declares another `[backend].source`.
    /// Completing the install would replace that backend and delete the model
    /// files under it, so it is refused and both directories are left as they
    /// were.
    InstallDirConflict,
}

/// Why an install failed: the phase it failed in, the error clients branch
/// on, and, when the daemon knows more than the error says, the reason in
/// words. The `reason` is what a client shows; `error` is what it decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallFailure {
    pub phase: InstallPhase,
    pub error: InstallError,
    pub reason: Option<String>,
}

impl InstallFailure {
    /// A failure whose `error` says all there is to say.
    #[must_use]
    pub fn new(phase: InstallPhase, error: InstallError) -> Self {
        Self {
            phase,
            error,
            reason: None,
        }
    }

    /// A failure with its reason in words.
    #[must_use]
    pub fn because(phase: InstallPhase, error: InstallError, reason: impl Into<String>) -> Self {
        Self {
            phase,
            error,
            reason: Some(reason.into()),
        }
    }
}

impl From<(InstallPhase, InstallError)> for InstallFailure {
    fn from((phase, error): (InstallPhase, InstallError)) -> Self {
        Self::new(phase, error)
    }
}

impl std::fmt::Display for InstallFailure {
    /// The reason when there is one, else what the error says.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            Some(reason) => f.write_str(reason),
            None => self.error.fmt(f),
        }
    }
}

impl std::fmt::Display for InstallError {
    /// Human-readable phrasing for the install-failure reason, so clients can
    /// surface it directly instead of printing the `Debug` variant name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Incompatible => "no compatible asset for this system",
            Self::DownloadFailed => "download failed",
            Self::AssetHashMismatch => "the downloaded file failed its integrity check",
            Self::TarballUnsafe => "the archive contained unsafe paths",
            Self::InstallIoError => "a filesystem error occurred during install",
            Self::ManifestInvalid => "the backend manifest was missing or invalid",
            Self::InstallDirConflict => "the install directory already holds a different backend",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(reason: Option<&str>) -> RegistryEvent {
        RegistryEvent::Failed {
            install_id: "ins_1".into(),
            source: "github.com/x/y".into(),
            phase: InstallPhase::Installing,
            error: InstallError::ManifestInvalid,
            reason: reason.map(Into::into),
        }
    }

    /// A failure's reason rides beside its error when the daemon has one, and
    /// is left out when it does not, so the payload is unchanged for every
    /// failure that has none.
    #[test]
    fn a_failure_carries_its_reason_only_when_there_is_one() {
        let with = serde_json::to_value(failed(Some("built for super-other"))).unwrap();
        assert_eq!(with["error"], "manifest_invalid");
        assert_eq!(with["reason"], "built for super-other");

        let without = serde_json::to_value(failed(None)).unwrap();
        assert!(without.get("reason").is_none(), "{without}");
    }

    /// An event from a daemon that predates the field still parses, with no
    /// reason.
    #[test]
    fn a_failure_without_a_reason_still_parses() {
        let event: RegistryEvent = serde_json::from_str(
            r#"{"type":"registry.install.failed","install_id":"ins_1","source":"s","phase":"installing","error":"manifest_invalid"}"#,
        )
        .unwrap();
        assert!(matches!(event, RegistryEvent::Failed { reason: None, .. }));
    }

    /// What a client shows: the reason when there is one, else the error.
    #[test]
    fn a_failure_reads_as_its_reason_or_its_error() {
        let plain = InstallFailure::new(InstallPhase::Downloading, InstallError::DownloadFailed);
        assert_eq!(plain.to_string(), "download failed");
        let explained = InstallFailure::because(
            InstallPhase::Installing,
            InstallError::ManifestInvalid,
            "built for super-other",
        );
        assert_eq!(explained.to_string(), "built for super-other");
    }
}
