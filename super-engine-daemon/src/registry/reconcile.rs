// SPDX-License-Identifier: GPL-3.0-only
//! Removing the duplicate backend directories discovery identified.
//!
//! Kept separate from discovery: reading a directory and deleting one are
//! different responsibilities, and destructive work does not belong inside a
//! function whose job is to scan. What a daemon has to repair afterwards —
//! a pointer at a directory that is gone — is its own; [`Reconciled::removed`]
//! is what it repairs from.

use std::path::{Path, PathBuf};

use super_engine_spec::manifest::Manifest;
use super_engine_spec::product::Product;

/// What one reconciliation pass did: the bytes carried across, and the
/// directories it actually removed.
///
/// The removals are reported rather than merely counted because a caller has
/// to repair anything that pointed at one of them, such as the daemon's active
/// backend. Basing that on "did the delete happen" rather than on any one
/// deleter's return value is what keeps the pointer and the filesystem from
/// disagreeing.
#[derive(Debug, Default)]
pub struct Reconciled {
    /// Bytes of model files moved from the losers into the winner.
    pub reclaimed: u64,
    /// The loser directories that no longer exist.
    pub removed: Vec<PathBuf>,
}

/// Move each loser's still-valid model files into `winner`, then remove it.
///
/// A directory whose manifest will not parse is left untouched: without a
/// readable file list there is no evidence it is the same backend, and that is
/// exactly the case where deleting would be a guess. A failed carry-over
/// aborts before the delete, so a partial move never costs the only copy.
pub async fn reconcile_dirs<P: Product>(losers: &[PathBuf], winner: &Path) -> Reconciled {
    let Ok(new) = Manifest::<P>::load(winner) else {
        log::error!(
            "Refusing to reconcile into {}: its manifest does not parse",
            winner.display()
        );
        return Reconciled::default();
    };

    let mut out = Reconciled::default();
    for loser in losers {
        let Ok(old) = Manifest::<P>::load(loser) else {
            log::error!(
                "Leaving {} in place: its manifest does not parse, so it cannot be \
                 confirmed a duplicate",
                loser.display()
            );
            continue;
        };
        let keep = crate::registry::carry_over::survivors(&old, &new);
        let bytes = match crate::registry::carry_over::carry(loser, winner, &keep).await {
            Ok(bytes) => {
                out.reclaimed += bytes;
                bytes
            }
            Err(e) => {
                log::error!(
                    "Leaving {} in place: carrying its model files into {} failed: {e}",
                    loser.display(),
                    winner.display()
                );
                continue;
            }
        };
        match tokio::fs::remove_dir_all(loser).await {
            Ok(()) => {
                log::info!(
                    "Reconciled duplicate {} ({}) into {} ({}), reclaiming {bytes} bytes",
                    loser.display(),
                    old.backend.version,
                    winner.display(),
                    new.backend.version,
                );
                out.removed.push(loser.clone());
            }
            Err(e) => log::error!("Failed to remove duplicate {}: {e}", loser.display()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super_engine_spec::test_product::TestProduct;

    #[tokio::test]
    async fn a_loser_hands_its_weights_over_before_it_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let toml = r#"
[backend]
    source     = "github.com/x/y"
    name       = "Y"
    version    = "1.0.0"
    kind       = "subprocess"
    entrypoint = "y"
    contract   = "v1"
    license    = "Apache-2.0"
    description = "Test backend."

[[assets.subprocess]]
    file   = "y.tar.gz"
    target = "x86_64-unknown-linux-gnu"
    accel  = ["cpu"]

[[models]]
    name                = "m"
    primary_language    = "en"
    supported_languages = ["en"]
    supported_devices   = ["cpu"]
    files = [
        { url = "https://h/a.bin", destination = "models/m/a.bin" },
    ]
"#;
        let winner = root.path().join("app.example.y");
        let loser = root.path().join("example-y");
        for d in [&winner, &loser] {
            std::fs::create_dir_all(d.join("models/m")).unwrap();
            std::fs::write(d.join("backend.toml"), toml).unwrap();
        }
        std::fs::write(loser.join("models/m/a.bin"), b"weights").unwrap();

        let done = super::reconcile_dirs::<TestProduct>(&[loser.clone()], &winner).await;

        assert_eq!(done.reclaimed, 7);
        assert_eq!(done.removed, vec![loser.clone()]);
        assert!(
            winner.join("models/m/a.bin").exists(),
            "weights moved across"
        );
        assert!(!loser.exists(), "the duplicate is gone");
    }

    /// Beyond the byte count: the moved file's actual content must survive
    /// the carry, byte for byte. This is the case the task exists for — a
    /// count matching by coincidence would not catch a truncated or
    /// corrupted move.
    #[tokio::test]
    async fn a_losers_weights_genuinely_reach_the_winner_byte_for_byte() {
        let root = tempfile::tempdir().unwrap();
        let toml = r#"
[backend]
    source     = "github.com/x/y"
    name       = "Y"
    version    = "1.0.0"
    kind       = "subprocess"
    entrypoint = "y"
    contract   = "v1"
    license    = "Apache-2.0"
    description = "Test backend."

[[assets.subprocess]]
    file   = "y.tar.gz"
    target = "x86_64-unknown-linux-gnu"
    accel  = ["cpu"]

[[models]]
    name                = "m"
    primary_language    = "en"
    supported_languages = ["en"]
    supported_devices   = ["cpu"]
    files = [
        { url = "https://h/a.bin", destination = "models/m/a.bin" },
    ]
"#;
        let winner = root.path().join("app.example.y");
        let loser = root.path().join("example-y");
        for d in [&winner, &loser] {
            std::fs::create_dir_all(d.join("models/m")).unwrap();
            std::fs::write(d.join("backend.toml"), toml).unwrap();
        }
        // Realistic-shaped content, not just a short literal: several
        // repeated blocks so a truncation or a swapped chunk would be caught
        // by the equality check below.
        let content: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        std::fs::write(loser.join("models/m/a.bin"), &content).unwrap();

        let done = super::reconcile_dirs::<TestProduct>(&[loser.clone()], &winner).await;

        assert_eq!(done.reclaimed, content.len() as u64);
        assert_eq!(done.removed, vec![loser.clone()]);
        let carried = std::fs::read(winner.join("models/m/a.bin")).unwrap();
        assert_eq!(
            carried, content,
            "the winner's copy must be byte-for-byte identical to the loser's"
        );
        assert!(!loser.exists(), "the duplicate is gone");
    }

    #[tokio::test]
    async fn an_unparseable_directory_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let winner = root.path().join("app.example.y");
        let loser = root.path().join("junk");
        std::fs::create_dir_all(&winner).unwrap();
        std::fs::create_dir_all(&loser).unwrap();
        std::fs::write(loser.join("backend.toml"), b"not toml {{{").unwrap();

        let done = super::reconcile_dirs::<TestProduct>(&[loser.clone()], &winner).await;

        assert_eq!(done.reclaimed, 0);
        assert!(
            done.removed.is_empty(),
            "nothing was removed, so nothing has to be repointed"
        );
        assert!(
            loser.exists(),
            "a directory we cannot read is never deleted"
        );
    }
}
