// SPDX-License-Identifier: GPL-3.0-only
//! The COSMIC applet the products share: where its releases come from, and
//! whether this install takes one.
//!
//! The applet has releases of its own, in [`REPO`], and every product's
//! installer installs the newest one for its channel. It never installs an
//! applet from the product's tarball. Two products install the same applet,
//! so an install never replaces a newer one than it found: a stable install
//! after a beta one would otherwise take the beta's applet back.

use std::path::Path;
use std::time::Duration;

use super_engine_protocol::SHARED_APPLET;
use super_engine_spec::version::{parse_version, update_available};

/// Where the applet's releases are published.
pub const REPO: &str = "github.com/super-libre/super-cosmic-applet";

/// How long the installed applet gets to print its version. It prints it and
/// exits before it touches the display, so this only bounds a hang.
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The version of the applet installed under `prefix`, from its `--version`
/// line (`super-cosmic-applet 0.1.0`).
///
/// `None` when it isn't installed, fails to run, or prints something else.
/// Every applet prints it, the ones products bundled before the applet had
/// releases included, so no stamp file is needed beside it.
pub async fn installed_version(prefix: &Path) -> Option<String> {
    let bin = prefix.join("bin").join(SHARED_APPLET);
    if !bin.is_file() {
        return None;
    }
    let output = tokio::time::timeout(
        VERSION_TIMEOUT,
        tokio::process::Command::new(&bin)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    version_from_output(&String::from_utf8_lossy(&output.stdout))
}

/// The version in a `--version` line: its last word, when that parses.
fn version_from_output(output: &str) -> Option<String> {
    let word = output.split_whitespace().last()?;
    parse_version(word).map(|_| word.to_string())
}

/// Whether to install the release tagged `candidate` over the applet
/// `installed`: when none is installed, or its version can't be read, or the
/// release is newer. An equal version is left alone, which also spares the
/// panel a restart.
#[must_use]
pub fn should_install(installed: Option<&str>, candidate: &str) -> bool {
    match installed {
        Some(have) if parse_version(have).is_some() => update_available(have, candidate),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_the_last_word_of_the_line() {
        assert_eq!(
            version_from_output("super-cosmic-applet 0.1.0\n").as_deref(),
            Some("0.1.0")
        );
        assert_eq!(
            version_from_output("super-cosmic-applet 0.2.0-beta.1").as_deref(),
            Some("0.2.0-beta.1")
        );
    }

    #[test]
    fn output_without_a_version_reads_as_none() {
        assert_eq!(version_from_output(""), None);
        assert_eq!(version_from_output("super-cosmic-applet"), None);
        assert_eq!(version_from_output("error: unexpected argument"), None);
    }

    #[test]
    fn an_applet_that_is_missing_or_unreadable_is_installed() {
        assert!(should_install(None, "v0.1.0"));
        assert!(should_install(Some("garbage"), "v0.1.0"));
    }

    #[test]
    fn a_newer_release_replaces_the_installed_applet() {
        assert!(should_install(Some("0.1.0"), "v0.1.1"));
        assert!(should_install(Some("0.2.0-beta.1"), "v0.2.0"));
    }

    #[test]
    fn an_applet_as_new_as_the_release_is_left_alone() {
        assert!(!should_install(Some("0.1.0"), "v0.1.0"));
    }

    /// A stable install after a beta one keeps the beta's newer applet.
    #[test]
    fn a_newer_installed_applet_is_never_replaced_by_an_older_release() {
        assert!(!should_install(Some("0.2.0-beta.1"), "v0.1.0"));
        assert!(!should_install(Some("0.3.0"), "v0.2.0"));
    }

    #[tokio::test]
    async fn no_installed_applet_has_no_version() {
        let prefix = std::env::temp_dir().join(format!(
            "super-engine-installer-applet-{}",
            std::process::id()
        ));
        assert_eq!(installed_version(&prefix).await, None);
    }

    /// The version comes from running the installed binary.
    #[tokio::test]
    async fn the_installed_version_comes_from_the_binary() {
        use std::os::unix::fs::PermissionsExt;
        let prefix = std::env::temp_dir().join(format!(
            "super-engine-installer-applet-bin-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&prefix);
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        let bin = prefix.join("bin").join(SHARED_APPLET);
        std::fs::write(
            &bin,
            "#!/bin/sh\n[ \"$1\" = --version ] && echo 'super-cosmic-applet 0.4.2'\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A script just written can briefly refuse to run (ETXTBSY) while
        // another test thread's fork still holds it open: retry, not flake.
        let mut version = None;
        for _ in 0..20 {
            version = installed_version(&prefix).await;
            if version.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(version.as_deref(), Some("0.4.2"));
        let _ = std::fs::remove_dir_all(&prefix);
    }
}
