// SPDX-License-Identifier: GPL-3.0-only
//! Hermetic, offline end-to-end test: drives the real `super-test-install`
//! binary through resolve → download → verify → stage against a mocked
//! GitHub API (`GITHUB_API_BASE`, honored by `Github::from_env` /
//! `accept_base_url` — loopback `http://` is allowed for exactly this),
//! with `--dry-run` so nothing is installed and no escalation happens.
//! Safe to run locally: no root, no keyring, no real network.

use std::io::Write;

/// `--components=all` is passed explicitly rather than relying on
/// auto-detection: auto-detect reads the *real* `/usr/local/bin` on
/// whatever machine runs this test (a dev box with the product already
/// installed would otherwise flip into "update mode" and require applet
/// assets the fixture below may or may not carry, making the test's
/// outcome depend on host state instead of the fixture). An explicit
/// selection makes `stage::plan_components` skip detection entirely.
const COMPONENTS_ARG: &str = "--components=all";

/// The release tag this test's fake GitHub API always returns.
const FAKE_TAG: &str = "v9.9.9-beta.1";

/// The add-on releases' tag: newer than any add-on a host running this test
/// may have installed, which the installer would otherwise keep, skipping
/// the download this test checks.
const FAKE_ADD_ON_TAG: &str = "v99.0.0-beta.1";

/// This host's Rust target triple, computed the same way
/// `resolve::target_triple` does — duplicated here because that module is
/// private to the installer.
fn target_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        other => panic!("e2e_dry_run: no fixture support for host arch {other}"),
    }
}

/// sha256 hex digest of `bytes`, via `ring` (a dev-dependency of this crate
/// — the crate's own production code hashes files, not in-memory bytes, via
/// `super_engine_spec::verify::file_sha256_hex`).
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex::encode(digest.as_ref())
}

/// A gzip'd tar of `files` (path, contents) under `dir`, as `name`.
fn tarball(dir: &std::path::Path, name: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let tree = dir.join(format!("{name}.tree"));
    for (path, contents) in files {
        let full = tree.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, contents).unwrap();
    }
    let tgz_path = dir.join(name);
    {
        let f = std::fs::File::create(&tgz_path).unwrap();
        let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        let mut tar = tar::Builder::new(enc);
        tar.append_dir_all(".", &tree).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }
    std::fs::read(&tgz_path).unwrap()
}

/// The product's release tarball, covering every file `--components=all`
/// requires of it (`stage::build_manifest`): the three daemon binaries, the
/// systemd unit, and the app binary, desktop file and icon. It carries no
/// applet: that comes from the applet's own release. The app metainfo is
/// optional in `build_manifest` and omitted.
fn product_tarball(dir: &std::path::Path, name: &str) -> Vec<u8> {
    tarball(
        dir,
        name,
        &[
            ("super-test-daemon", b"#!/bin/sh\necho fake\n"),
            ("super-test-cli", b"#!/bin/sh\necho fake\n"),
            ("super-test-consent", b"#!/bin/sh\necho fake\n"),
            ("super-test-app", b"#!/bin/sh\necho fake\n"),
            ("systemd/super-test.service", b"[Unit]\nDescription=fake\n"),
            (
                "resources/super-test-app.desktop",
                b"[Desktop Entry]\nName=Super Test\n",
            ),
            (
                "resources/icons/hicolor/scalable/apps/super-test-app.svg",
                b"<svg/>",
            ),
        ],
    )
}

/// The applet release's tarball: the binary, one launcher entry (at least one
/// is required, F5) and the icon.
fn applet_tarball(dir: &std::path::Path, name: &str) -> Vec<u8> {
    tarball(
        dir,
        name,
        &[
            ("super-test-shared-applet", b"#!/bin/sh\necho fake\n"),
            (
                "resources/super-test-shared-applet-full.desktop",
                b"[Desktop Entry]\nName=Super Applet\n",
            ),
            (
                "resources/icons/hicolor/scalable/apps/super-test-shared-applet.svg",
                b"<svg/>",
            ),
        ],
    )
}

/// The extension release's tarball: the extension's directory, its
/// `metadata.json` naming the test product's extension.
fn extension_tarball(dir: &std::path::Path, name: &str) -> Vec<u8> {
    tarball(
        dir,
        name,
        &[
            (
                "metadata.json",
                br#"{"uuid": "super-test@example.com", "version-name": "99.0.0-beta.1"}"#,
            ),
            ("extension.js", b"export default class {}\n"),
            ("schemas/gschemas.compiled", b"GVariant"),
        ],
    )
}

/// A GitHub releases listing of one prerelease, `tag`, with a tarball and
/// its `SHA256SUMS`, served from `base` at `/<path>/tarball` and `/<path>/sums`.
fn releases_json(
    base: &str,
    path: &str,
    tag: &str,
    tarball: (&str, usize),
    sums_len: usize,
) -> String {
    serde_json::json!([{
        "tag_name": tag,
        "draft": false,
        "prerelease": true,
        "assets": [
            {
                "name": tarball.0,
                "browser_download_url": format!("{base}/{path}/tarball"),
                "size": tarball.1,
            },
            {
                "name": "SHA256SUMS",
                "browser_download_url": format!("{base}/{path}/sums"),
                "size": sums_len,
            },
        ],
    }])
    .to_string()
}

/// One release served by the fake GitHub API: its repo, the path its assets
/// are served under, its tag, and its tarball's name and bytes.
struct FakeRelease<'a> {
    repo: &'a str,
    path: &'a str,
    tag: &'a str,
    tarball_name: String,
    tarball: Vec<u8>,
}

/// Serve `release`'s listing, tarball and `SHA256SUMS` from `server`, each
/// expected to be asked for once.
async fn serve(server: &mut mockito::Server, release: &FakeRelease<'_>) -> Vec<mockito::Mock> {
    let base = server.url();
    let sums = format!(
        "{}  {}\n",
        sha256_hex(&release.tarball),
        release.tarball_name
    );
    let listing = releases_json(
        &base,
        release.path,
        release.tag,
        (&release.tarball_name, release.tarball.len()),
        sums.len(),
    );
    vec![
        server
            .mock(
                "GET",
                format!("/repos/{}/releases?per_page=100", release.repo).as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(listing)
            .expect(1)
            .create_async()
            .await,
        server
            .mock("GET", format!("/{}/tarball", release.path).as_str())
            .with_status(200)
            .with_body(&release.tarball)
            .expect(1)
            .create_async()
            .await,
        server
            .mock("GET", format!("/{}/sums", release.path).as_str())
            .with_status(200)
            .with_body(sums)
            .expect(1)
            .create_async()
            .await,
    ]
}

/// The product's release, as the fake GitHub API serves it.
fn product_release(dir: &std::path::Path) -> FakeRelease<'static> {
    let tarball_name = format!("super-test-{}-beta.tar.gz", target_triple());
    FakeRelease {
        repo: "example/super-test",
        path: "product",
        tag: FAKE_TAG,
        tarball: product_tarball(dir, &tarball_name),
        tarball_name,
    }
}

/// Run `super-test-install --dry-run` against the fake GitHub API at `base`
/// with `components`, and return its JSON events, checking it succeeded.
async fn dry_run(base: String, components: &'static str) -> Vec<serde_json::Value> {
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_super-test-install"))
            .env("GITHUB_API_BASE", base)
            .args([
                "--non-interactive",
                "--json-progress",
                "--beta",
                "--dry-run",
                components,
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    if !out.status.success() {
        let _ = std::io::stderr().write_all(&out.stderr);
    }
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let events: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad JSON line {l:?}: {e}")))
        .collect();
    assert!(!events.is_empty(), "expected at least one JSON event");
    events
}

/// The components the `complete` event, the last, says were installed.
fn completed_components(events: &[serde_json::Value]) -> Vec<String> {
    let complete = events.last().unwrap();
    assert_eq!(complete["event"], "complete");
    assert_eq!(complete["installed_version"], FAKE_TAG);
    complete["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn dry_run_resolves_downloads_verifies_and_stages_against_a_mocked_release() {
    // Removed when the test ends, failed or not.
    let tmp = tempfile::Builder::new()
        .prefix("super-engine-installer-e2e-")
        .tempdir()
        .unwrap();
    let dir = tmp.path();
    let applet_tarball_name = format!("super-test-shared-applet-{}-beta.tar.gz", target_triple());
    let applet = FakeRelease {
        repo: "example/super-test-cosmic-applet",
        path: "applet",
        tag: FAKE_ADD_ON_TAG,
        tarball: applet_tarball(dir, &applet_tarball_name),
        tarball_name: applet_tarball_name,
    };

    let mut server = mockito::Server::new_async().await;
    let mut mocks = serve(&mut server, &product_release(dir)).await;
    mocks.extend(serve(&mut server, &applet).await);

    let events = dry_run(server.url(), COMPONENTS_ARG).await;
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "phase" && e["phase"] == "download"),
        "expected a download phase event: {events:?}"
    );
    assert!(
        events.iter().any(|e| e["event"] == "progress"),
        "expected at least one progress event: {events:?}"
    );
    assert_eq!(completed_components(&events), ["daemon", "app", "applet"]);

    // Both releases were resolved, and both tarballs downloaded and checked:
    // the applet's from its own repo, since the product's carries none.
    for mock in &mocks {
        mock.assert_async().await;
    }
}

/// The extension comes from its own repo, as `<name>-noarch[-beta].tar.gz`,
/// and stages without the product's other components.
#[tokio::test]
async fn dry_run_stages_the_extension_from_its_own_release() {
    let tmp = tempfile::Builder::new()
        .prefix("super-engine-installer-e2e-extension-")
        .tempdir()
        .unwrap();
    let dir = tmp.path();
    let extension_tarball_name = "super-test-gnome-shell-extension-noarch-beta.tar.gz".to_string();
    let extension = FakeRelease {
        repo: "example/super-test-gnome-shell-extension",
        path: "extension",
        tag: FAKE_ADD_ON_TAG,
        tarball: extension_tarball(dir, &extension_tarball_name),
        tarball_name: extension_tarball_name,
    };

    let mut server = mockito::Server::new_async().await;
    let mut mocks = serve(&mut server, &product_release(dir)).await;
    mocks.extend(serve(&mut server, &extension).await);

    let events = dry_run(server.url(), "--components=extension").await;
    assert_eq!(completed_components(&events), ["extension"]);
    for mock in &mocks {
        mock.assert_async().await;
    }
}
