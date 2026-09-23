// SPDX-License-Identifier: GPL-3.0-only
//! What a daemon tells its consent helper, and what the helper answers.
//!
//! On Linux the daemon puts the consent question on screen by running a
//! helper installed beside it ([`ProductSpec::consent_helper`]). The request
//! travels in environment variables and the answer comes back as one word on
//! the helper's stdout. The two binaries ship together but are built from
//! different crates, so the names they agree on are written once, here.
//!
//! Each variable is the product's, e.g. `SUPER_STT_AUTH_APP_NAME` for
//! [`APP_NAME`]: `product.env(consent::APP_NAME)`.
//!
//! [`ProductSpec::consent_helper`]: crate::ProductSpec::consent_helper

/// The app name the caller declared. Untrusted: the caller chose it.
pub const APP_NAME: &str = "AUTH_APP_NAME";

/// The requested scopes, separated by spaces.
pub const SCOPES: &str = "AUTH_SCOPES";

/// The caller's executable, as the kernel resolved it. Set for a caller on
/// the Unix socket, never together with [`WEB_ORIGIN`].
pub const EXE_PATH: &str = "AUTH_EXE_PATH";

/// The caller's flatpak application id. Set only for a caller inside a
/// flatpak sandbox, whose [`EXE_PATH`] is a path inside that sandbox.
pub const FLATPAK_APP_ID: &str = "AUTH_FLATPAK_APP_ID";

/// The browser-reported origin of a caller on the TCP listener. Set instead
/// of [`EXE_PATH`], never beside it, and a helper that finds both believes
/// this one.
pub const WEB_ORIGIN: &str = "AUTH_WEB_ORIGIN";

/// Milliseconds after which a debug build of the helper approves on its own.
/// For tests that need to see the dialog open; a release build ignores it.
pub const AUTO_APPROVE_AFTER_MS: &str = "AUTH_AUTO_APPROVE_AFTER_MS";

/// The helper's answer when the user allowed the request.
pub const ALLOW: &str = "allow";

/// The helper's answer when the user denied the request.
pub const DENY: &str = "deny";

/// The helper's answer when the user closed the dialog without choosing.
/// Anything the daemon does not recognize reads as this too.
pub const DISMISSED: &str = "dismissed";

#[cfg(test)]
mod tests {
    use crate::{SUPER_STT, SUPER_TTS};

    /// The variable names are the product's own, so two daemons' helpers can
    /// never read each other's requests out of a shared environment.
    #[test]
    fn each_product_names_its_own_variables() {
        assert_eq!(SUPER_STT.env(super::APP_NAME), "SUPER_STT_AUTH_APP_NAME");
        assert_eq!(SUPER_TTS.env(super::APP_NAME), "SUPER_TTS_AUTH_APP_NAME");
        assert_eq!(
            SUPER_STT.env(super::AUTO_APPROVE_AFTER_MS),
            "SUPER_STT_AUTH_AUTO_APPROVE_AFTER_MS"
        );
    }
}
