// SPDX-License-Identifier: GPL-3.0-only
//! A temp directory for one test, removed when the test ends.

use std::path::Path;

/// A fresh directory under the system temp dir, named `<prefix>` and a random
/// suffix, removed with everything in it when dropped: when the test returns,
/// and when it panics. It derefs to its path, so it goes wherever a `&Path`
/// does.
///
/// Before this, each test left its directory behind, and one of them holds a
/// copy of the test binary itself: every run left ~140 MB in `/tmp`, which
/// on most systems is RAM.
pub struct TestDir(tempfile::TempDir);

impl TestDir {
    pub fn new(prefix: &str) -> Self {
        Self::new_in(prefix, &std::env::temp_dir())
    }

    /// The same, under `parent`.
    pub fn new_in(prefix: &str, parent: &Path) -> Self {
        Self(
            tempfile::Builder::new()
                .prefix(prefix)
                .tempdir_in(parent)
                .expect("create a test directory"),
        )
    }
}

impl std::ops::Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.0.path()
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.0.path()
    }
}
