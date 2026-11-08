// SPDX-License-Identifier: GPL-3.0-only
//! What an installed backend's `backend.toml` says it downloaded, read without
//! holding it to any product's rules.
//!
//! A backend installed by a product this one replaced has a manifest written
//! for that product: another `product`, an older contract, keys the current
//! spec refuses. [`Manifest::load`](crate::manifest::Manifest::load) rightly
//! refuses it, so nothing serves it. But an update that replaces it must still
//! find it, and carry over the model files it already downloaded, or a user's
//! first update re-downloads gigabytes that are already on disk. For that only
//! two things matter: which backend it is (`[backend].source`) and which file
//! sits at each destination (`[[models.files]]`'s `destination` and `url`).
//! Every other key is ignored, whatever it says.

use std::path::Path;

use serde::Deserialize;

/// The identity and declared files of an installed backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledFiles {
    /// `[backend].source`.
    pub source: String,
    /// Each `[[models]]` entry's files, as `(destination, url)`, in manifest
    /// order.
    pub models: Vec<Vec<(String, String)>>,
}

#[derive(Deserialize)]
struct Raw {
    backend: RawBackend,
    #[serde(default)]
    models: Vec<RawModel>,
}

#[derive(Deserialize)]
struct RawBackend {
    source: String,
}

#[derive(Deserialize)]
struct RawModel {
    #[serde(default)]
    files: Vec<RawFile>,
}

#[derive(Deserialize)]
struct RawFile {
    destination: String,
    url: String,
}

impl InstalledFiles {
    /// Read `<dir>/backend.toml`, or `None` when it cannot be read or does not
    /// name a source. A destination that is not a safe relative path is
    /// dropped: it is joined onto a directory, and must not climb out of it.
    #[must_use]
    pub fn load(dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(dir.join("backend.toml")).ok()?;
        Self::parse(&text)
    }

    /// [`load`](Self::load) for manifest text.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let raw: Raw = toml::from_str(text).ok()?;
        Some(Self {
            source: raw.backend.source,
            models: raw
                .models
                .into_iter()
                .map(|model| {
                    model
                        .files
                        .into_iter()
                        .filter(|f| crate::is_safe_relative_path(&f.destination))
                        .map(|f| (f.destination, f.url))
                        .collect()
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::InstalledFiles;

    /// A manifest another product wrote, in a contract this one never knew,
    /// still says which backend it is and what it downloaded.
    #[test]
    fn reads_a_manifest_no_product_would_accept() {
        let files = InstalledFiles::parse(
            r#"
[backend]
source = "github.com/x/whisper"
product = "super-stt"
contract = "v4"
unknown_key = true

[[models]]
name = "tiny"
provider = "LocalWhisper"

[[models.files]]
destination = "models/tiny/model.bin"
url = "https://example.com/tiny.bin"
sha256 = "00"

[[models.files]]
destination = "../escape"
url = "https://example.com/evil"
"#,
        )
        .expect("parses");
        assert_eq!(files.source, "github.com/x/whisper");
        assert_eq!(
            files.models,
            vec![vec![(
                "models/tiny/model.bin".to_string(),
                "https://example.com/tiny.bin".to_string()
            )]],
            "an unsafe destination is dropped"
        );
    }

    #[test]
    fn a_manifest_without_a_source_is_not_one() {
        assert_eq!(InstalledFiles::parse("[backend]\nname = \"x\"\n"), None);
        assert_eq!(InstalledFiles::parse("not toml"), None);
    }
}
