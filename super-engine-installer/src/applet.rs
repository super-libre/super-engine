// SPDX-License-Identifier: GPL-3.0-only
//! A product's COSMIC applet: where its releases come from, and whether this
//! install takes one.
//!
//! The applet has releases of its own, in [`CosmicApplet::repo`], and the
//! product's installer installs the newest one for its channel. It never
//! installs an applet from the product's tarball. Products may share one
//! applet, so an install never replaces a newer one than it found: a stable
//! install after a beta one would otherwise take the beta's applet back.

use std::path::Path;
use std::time::Duration;

use super_engine_spec::version::parse_version;

/// A product's COSMIC applet.
#[derive(Debug, Clone, Copy)]
pub struct CosmicApplet {
    /// Where its releases are published, e.g.
    /// `github.com/super-libre/super-cosmic-applet`.
    pub repo: &'static str,
    /// Its binary's name, which its launcher entries and icon are named
    /// after, and its release tarballs start with.
    pub name: &'static str,
}

/// How long the installed applet gets to print its version. It prints it and
/// exits before it touches the display, so this only bounds a hang.
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The version of `applet` installed under `prefix`, from its `--version`
/// line (`super-cosmic-applet 0.1.0`).
///
/// `None` when it isn't installed, fails to run, or prints something else.
/// Every applet prints it, the ones products bundled before the applet had
/// releases included, so no stamp file is needed beside it.
pub async fn installed_version(prefix: &Path, applet: &CosmicApplet) -> Option<String> {
    let bin = prefix.join("bin").join(applet.name);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TestDir;

    const APPLET: CosmicApplet = CosmicApplet {
        repo: "github.com/example/super-test-cosmic-applet",
        name: "super-test-shared-applet",
    };

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

    #[tokio::test]
    async fn no_installed_applet_has_no_version() {
        let prefix = TestDir::new("super-engine-installer-applet-");
        assert_eq!(installed_version(&prefix, &APPLET).await, None);
    }

    /// The version comes from running the installed binary.
    #[tokio::test]
    async fn the_installed_version_comes_from_the_binary() {
        use std::os::unix::fs::PermissionsExt;
        let prefix = TestDir::new("super-engine-installer-applet-bin-");
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        let bin = prefix.join("bin").join(APPLET.name);
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
            version = installed_version(&prefix, &APPLET).await;
            if version.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(version.as_deref(), Some("0.4.2"));
    }
}
