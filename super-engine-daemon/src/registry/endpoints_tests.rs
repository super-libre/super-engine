// SPDX-License-Identifier: GPL-3.0-only
//! Tests for the registry endpoints, run against a made-up daemon.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;
use super_engine_protocol::test_product::TEST;
use super_engine_spec::index::{Index, IndexAsset, IndexAssets};
use super_engine_spec::test_product::{IndexModel, TestProduct};
use tokio::sync::RwLock;

// A bus with the core topics only.
crate::event_topics! {}

/// Nothing listens here, so a test that reaches the network fails fast.
const UNREACHABLE: &str = "http://127.0.0.1:1/never-fetched";

fn daemon() -> Daemon {
    Daemon {
        product: &TEST,
        version: "1.0.0",
        user_agent: "super-engine-test",
    }
}

/// A daemon that records what the endpoints asked of it.
struct TestHost {
    backends: RwLock<Vec<DiscoveredBackend<TestProduct>>>,
    backends_dir: PathBuf,
    events: Arc<EventBus>,
    replaced: Mutex<Vec<(Vec<PathBuf>, PathBuf)>>,
    refreshes: AtomicUsize,
}

impl TestHost {
    fn new(backends_dir: &Path) -> Self {
        Self {
            backends: RwLock::default(),
            backends_dir: backends_dir.to_path_buf(),
            events: Arc::new(EventBus::new()),
            replaced: Mutex::default(),
            refreshes: AtomicUsize::new(0),
        }
    }
}

impl RegistryHost for TestHost {
    type Product = TestProduct;
    type Events = EventBus;

    fn daemon(&self) -> Daemon {
        daemon()
    }

    fn events(&self) -> Arc<EventBus> {
        Arc::clone(&self.events)
    }

    fn backends(&self) -> &RwLock<Vec<DiscoveredBackend<TestProduct>>> {
        &self.backends
    }

    async fn backends_dir(&self) -> PathBuf {
        self.backends_dir.clone()
    }

    async fn backend_dirs_replaced(&self, removed: &[PathBuf], winner: &Path) {
        self.replaced
            .lock()
            .push((removed.to_vec(), winner.to_path_buf()));
    }

    async fn refresh_backends(&self) {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
    }
}

fn registry_at(host: TestHost, index_url: &str, cache: &Path) -> Registry<TestHost> {
    super_engine_forge::install_crypto_provider();
    Registry::new(
        Arc::new(host),
        Client::new(
            daemon(),
            index_url,
            cache.join("index.json"),
            Duration::from_secs(60),
        ),
    )
}

/// A `wasm` entry for `source` at `version`; with `asset`, one any host can
/// install.
fn wasm_entry(source: &str, version: &str, asset: bool) -> IndexBackend<IndexModel> {
    IndexBackend {
        id: source.rsplit('/').next().unwrap_or(source).to_owned(),
        backend_id: None,
        source: source.to_owned(),
        version: version.to_owned(),
        tag: format!("v{version}"),
        name: "Thing".to_owned(),
        description: Some("Does a thing.".to_owned()),
        license: String::new(),
        kind: "wasm".to_owned(),
        contract: "v1".to_owned(),
        min_client: None,
        entrypoint: "thing.wasm".to_owned(),
        allowed_hosts: vec![],
        online: false,
        supports_gpu: false,
        supports_cpu: true,
        models: vec![],
        secrets: vec![],
        options: vec![],
        assets: IndexAssets {
            wasm: asset.then(|| IndexAsset {
                url: format!("{UNREACHABLE}/thing.wasm"),
                size: 1,
                sha256: "0".repeat(64),
            }),
            subprocess: vec![],
        },
        index_stale: None,
        manifest: None,
    }
}

fn discovered(dir: &str, source: &str, version: &str) -> DiscoveredBackend<TestProduct> {
    DiscoveredBackend {
        dir: PathBuf::from("/backends").join(dir),
        source: source.to_owned(),
        id: None,
        name: "Thing".to_owned(),
        description: String::new(),
        version: version.to_owned(),
        kind: "subprocess".to_owned(),
        entrypoint: "thing".to_owned(),
        allowed_hosts: Vec::new(),
        secrets: Vec::new(),
        options: Vec::new(),
        capabilities: Default::default(),
        models: Vec::new(),
    }
}

async fn body_of(resp: Response) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    (status, serde_json::from_slice(&bytes).expect("a JSON body"))
}

// ---------------------------------------------------------------------------
// The error envelope
// ---------------------------------------------------------------------------

/// The envelope carries the machine-readable `error_code` (and `status`), and
/// keeps the `error` key clients written before it still read.
#[tokio::test]
async fn an_error_carries_error_code_and_the_legacy_key() {
    let (status, v) = body_of(error(StatusCode::NOT_FOUND, "not_found")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "not_found");
    assert_eq!(v["error"], "not_found");
    assert!(v.get("message").is_none(), "no message, no key: {v}");

    let (status, v) = body_of(error_with_message(
        StatusCode::BAD_REQUEST,
        "bad_request",
        "provide exactly one of source, repo_url, local_path",
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "bad_request");
    assert_eq!(v["error"], "bad_request");
    assert_eq!(
        v["message"],
        "provide exactly one of source, repo_url, local_path"
    );
}

// ---------------------------------------------------------------------------
// What the listing reports
// ---------------------------------------------------------------------------

/// What this adds to the semver comparison: "not installed" is not an update,
/// and a downgrade or an unreadable version never becomes one.
#[test]
fn only_an_installed_older_version_has_an_update() {
    assert!(update_available(Some("0.1.0"), "0.1.1", true));
    assert!(update_available(Some("v1.0.0"), "1.0.1", true));

    // Not installed: the client is offered an install, not an update.
    assert!(!update_available(None, "0.1.1", true));
    // Already current, and a stale index that would prompt a downgrade.
    assert!(!update_available(Some("0.1.1"), "0.1.1", true));
    assert!(!update_available(Some("0.2.0"), "0.1.1", true));
    // Neither side is guessed at when it cannot be parsed.
    assert!(!update_available(Some("1.0.0"), "nightly", true));
    assert!(!update_available(Some(""), "1.0.0", true));
}

/// A newer release this daemon cannot install is not an update on offer. The
/// Update button it would otherwise draw leads only to `422 incompatible`.
#[test]
fn an_incompatible_release_is_not_offered_as_an_update() {
    assert!(update_available(Some("0.1.0"), "0.2.0", true));
    assert!(!update_available(Some("0.1.0"), "0.2.0", false));
}

/// The install directory is named after the repo and the index id is not, so
/// keying on the directory never matched. Matching on `source` is what makes a
/// custom-path install updatable.
#[test]
fn a_directory_not_named_after_the_index_id_still_reports_its_version() {
    let catalog = vec![discovered(
        "app.example.thing",
        "github.com/x/thing",
        "0.1.0",
    )];
    assert_eq!(
        installed_version_for_source(&catalog, "github.com/x/thing"),
        Some("0.1.0".to_owned())
    );
}

#[test]
fn a_source_absent_from_the_catalog_has_no_installed_version() {
    let catalog = vec![discovered("other", "github.com/x/other", "0.1.0")];
    assert_eq!(
        installed_version_for_source(&catalog, "github.com/x/thing"),
        None
    );
}

/// The catalog, end to end: an installed backend with a newer release is an
/// update, and an entry this host cannot run is left out unless asked for,
/// with its reason.
#[tokio::test]
async fn the_listing_reports_updates_and_hides_what_this_host_cannot_run() {
    let mut server = mockito::Server::new_async().await;
    let index = Index {
        schema_version: 1,
        generated_at: "2026-09-24T00:00:00Z".to_owned(),
        min_client: "0.1.0".to_owned(),
        backends: vec![
            wasm_entry("github.com/x/thing", "0.2.0", true),
            wasm_entry("github.com/x/broken", "1.0.0", false),
        ],
    };
    server
        .mock("GET", "/index.json")
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&index).unwrap())
        .create_async()
        .await;

    let root = tempfile::tempdir().unwrap();
    let host = TestHost::new(root.path());
    host.backends.write().await.push(discovered(
        "app.example.thing",
        "github.com/x/thing",
        "0.1.0",
    ));
    let registry = registry_at(host, &format!("{}/index.json", server.url()), root.path());

    let query = ListQuery {
        include_incompatible: false,
        kind: None,
        online: None,
        q: None,
    };
    let (status, v) = body_of(list(&registry, &query).await).await;
    assert_eq!(status, StatusCode::OK);
    let backends = v["backends"].as_array().unwrap();
    assert_eq!(backends.len(), 1, "only what this host can run: {v}");
    assert_eq!(backends[0]["source"], "github.com/x/thing");
    assert_eq!(backends[0]["installed_version"], "0.1.0");
    assert_eq!(backends[0]["update_available"], true);
    assert_eq!(backends[0]["compatibility"]["compatible"], true);

    let query = ListQuery {
        include_incompatible: true,
        ..query
    };
    let (_, v) = body_of(list(&registry, &query).await).await;
    let broken = v["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["source"] == "github.com/x/broken")
        .expect("listed when asked for");
    assert_eq!(broken["compatibility"]["compatible"], false);
    assert_eq!(
        broken["compatibility"]["reason"],
        "wasm backend missing wasm asset"
    );
    assert_eq!(broken["update_available"], false);
}

#[tokio::test]
async fn a_listing_with_no_index_is_registry_unavailable() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry_at(TestHost::new(root.path()), UNREACHABLE, root.path());
    let query = ListQuery {
        include_incompatible: false,
        kind: None,
        online: None,
        q: None,
    };
    let (status, v) = body_of(list(&registry, &query).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error_code"], "registry_unavailable");
}

/// A failed refresh is announced, so a second client learns of it too.
#[tokio::test]
async fn a_failed_refresh_is_announced() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry_at(TestHost::new(root.path()), UNREACHABLE, root.path());
    let mut rx = registry.host.events.subscribe(Topic::RegistryInstall);

    let (status, v) = body_of(refresh(&registry).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error_code"], "registry_unavailable");

    let (_, event) = rx.recv_json().await.unwrap();
    assert_eq!(event["type"], "registry.refresh.failed");
}

// ---------------------------------------------------------------------------
// Resolving an install source
// ---------------------------------------------------------------------------

/// The Add-a-backend sheet posts a pasted `repo_url` and nothing else, and
/// requiring `forge` beside it made every such install answer `400` without
/// reaching the forge at all.
#[test]
fn a_pasted_github_url_needs_no_declared_forge() {
    for url in [
        "https://github.com/owner/backend",
        "github.com/owner/backend",
        "https://github.com/owner/backend.git",
        "https://GitHub.com/owner/backend/",
    ] {
        assert_eq!(install_forge(None, url).ok(), Some(Forge::Github), "{url}");
    }
}

/// The escape hatch for a host the map does not know: a GitHub Enterprise
/// server, reached by pointing `GITHUB_API_BASE` at its API.
#[test]
fn a_declared_forge_wins_over_the_host() {
    assert_eq!(
        install_forge(Some(Forge::Github), "github.mycorp.example/owner/backend").ok(),
        Some(Forge::Github)
    );
}

/// Guessing GitHub here would not fail loudly: the adapter addresses a repo by
/// owner and name alone, so it would fetch a *different* project of the same
/// name from api.github.com and install it.
#[test]
fn an_unserved_host_is_rejected_rather_than_guessed() {
    let (status, code, _) = install_forge(None, "https://gitlab.com/owner/backend")
        .expect_err("no adapter serves gitlab.com");
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, "unsupported_forge")
    );
}

#[test]
fn a_malformed_repo_url_answers_bad_repo_url() {
    let (status, code, _) =
        install_forge(None, "owner/backend").expect_err("not <host>/<owner>/<repo>");
    assert_eq!((status, code), (StatusCode::BAD_REQUEST, "bad_repo_url"));
}

// ---------------------------------------------------------------------------
// Install and update
// ---------------------------------------------------------------------------

fn install_body(
    source: Option<&str>,
    repo_url: Option<&str>,
    local_path: Option<&str>,
) -> Option<Json<InstallBody>> {
    Some(Json(InstallBody {
        source: source.map(str::to_owned),
        repo_url: repo_url.map(str::to_owned),
        local_path: local_path.map(str::to_owned),
        forge: None,
    }))
}

#[tokio::test]
async fn an_install_needs_exactly_one_source() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry_at(TestHost::new(root.path()), UNREACHABLE, root.path());

    let (status, v) = body_of(install(&registry, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "missing_body");

    for body in [
        install_body(None, None, None),
        install_body(Some("github.com/x/thing"), Some("github.com/x/thing"), None),
    ] {
        let (status, v) = body_of(install(&registry, body).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error_code"], "bad_request");
    }
}

/// A second install of a backend already installing is refused, and the
/// refusal leaves the first one's claim in place.
#[tokio::test]
async fn a_second_install_of_the_same_source_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry_at(TestHost::new(root.path()), UNREACHABLE, root.path());
    let first = InFlightMarker::acquire(&registry.in_flight, "github.com/x/thing").unwrap();

    let (status, v) = body_of(
        install(
            &registry,
            install_body(Some("github.com/x/thing"), None, None),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(v["error_code"], "install_in_progress");
    assert!(registry.in_flight.lock().contains("github.com/x/thing"));

    let (status, v) = body_of(
        update(
            &registry,
            Some(Json(UpdateBody {
                source: "github.com/x/thing".to_owned(),
            })),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(v["error_code"], "update_in_progress");

    drop(first);
    assert!(registry.in_flight.lock().is_empty());
}

/// An install that fails before it starts releases its claim, so a retry is
/// not refused with a stale `409`.
#[tokio::test]
async fn a_failed_install_releases_its_source() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry_at(TestHost::new(root.path()), UNREACHABLE, root.path());

    let (status, v) = body_of(
        install(
            &registry,
            install_body(Some("github.com/x/thing"), None, None),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error_code"], "registry_unavailable");
    assert!(registry.in_flight.lock().is_empty());

    let (status, v) = body_of(update(&registry, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "missing_body");
}

/// `select` already knows why a host cannot take a build, and when the cause is
/// a contract generation the daemon predates, that sentence names the remedy.
/// Install and update both send it as the `message` of their `422`.
#[tokio::test]
async fn an_incompatible_build_is_refused_with_its_reason() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry_at(TestHost::new(root.path()), UNREACHABLE, root.path());

    let entry = wasm_entry("github.com/x/broken", "1.0.0", false);
    let Err(resp) = select_install(&registry, &entry, None) else {
        panic!("an entry with no asset has nothing to install");
    };
    let (status, v) = body_of(*resp).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error_code"], "incompatible");
    assert_eq!(v["message"], "wasm backend missing wasm asset");

    let mut entry = wasm_entry("github.com/x/future", "1.0.0", true);
    entry.contract = "v9".to_owned();
    entry.min_client = Some("2.0.0".to_owned());
    let Err(resp) = select_install(&registry, &entry, None) else {
        panic!("a contract this daemon predates is not installable");
    };
    let (_, v) = body_of(*resp).await;
    assert_eq!(
        v["message"],
        "needs Super Test 2.0.0 or newer (backend contract v9); this is 1.0.0"
    );
}

/// Stage `dir` as a backend an operator built themselves.
fn stage_backend(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("backend.toml"),
        r#"
[backend]
source = "github.com/x/thing"
id = "app.example.thing"
name = "Thing"
version = "0.3.0"
kind = "subprocess"
entrypoint = "thing"
contract = "v1"
description = "Test backend."
"#,
    )
    .unwrap();
    std::fs::write(dir.join("thing"), b"#!/bin/sh\n").unwrap();
}

/// A local import, end to end: accepted with its warning, installed in the
/// background, announced, rescanned, and its claim released.
#[tokio::test]
async fn a_local_import_installs_in_the_background() {
    let root = tempfile::tempdir().unwrap();
    let backends_dir = root.path().join("backends");
    let staged = root.path().join("staged");
    stage_backend(&staged);

    let registry = registry_at(TestHost::new(&backends_dir), UNREACHABLE, root.path());
    let mut rx = registry.host.events.subscribe(Topic::RegistryInstall);

    let staged_path = staged.to_str().unwrap();
    let (status, v) =
        body_of(install(&registry, install_body(None, None, Some(staged_path))).await).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["source"], "github.com/x/thing");
    assert_eq!(v["warning"], "unverified_source");
    assert_eq!(v["selected_asset"]["accel"], "local");
    let install_id = v["install_id"].as_str().unwrap().to_owned();

    let completed = loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), rx.recv_json())
            .await
            .expect("the install finishes")
            .unwrap();
        if event["type"] != "registry.install.progress" {
            break event;
        }
    };
    assert_eq!(
        completed["type"], "registry.install.completed",
        "{completed}"
    );
    assert_eq!(completed["install_id"], install_id.as_str());
    // Keyed by what the client sent.
    assert_eq!(completed["source"], staged_path);
    assert_eq!(completed["version"], "0.3.0");

    assert!(backends_dir.join("app.example.thing/backend.toml").exists());
    assert_eq!(registry.host.refreshes.load(Ordering::SeqCst), 1);
    assert!(registry.in_flight.lock().is_empty());
}

/// Lay out an old directory serving `source` and the new one an install just
/// wrote, as the pipeline leaves them right before it retires the old.
fn migrated_layout(root: &Path, old: &str, new: &str) {
    stage_backend(&root.join(old));
    std::fs::create_dir_all(root.join(new)).unwrap();
}

#[tokio::test]
async fn a_retired_directory_is_reported_to_the_host() {
    let root = tempfile::tempdir().unwrap();
    migrated_layout(root.path(), "thing", "app.example.thing");
    let host = TestHost::new(root.path());

    retire_and_repoint(
        &host,
        root.path(),
        "github.com/x/thing",
        "app.example.thing",
    )
    .await;

    assert!(!root.path().join("thing").exists());
    assert_eq!(
        *host.replaced.lock(),
        vec![(
            vec![root.path().join("thing")],
            root.path().join("app.example.thing")
        )]
    );
}

#[tokio::test]
async fn an_install_with_no_predecessor_repoints_nothing() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("app.example.thing")).unwrap();
    let host = TestHost::new(root.path());

    retire_and_repoint(
        &host,
        root.path(),
        "github.com/x/thing",
        "app.example.thing",
    )
    .await;

    assert!(host.replaced.lock().is_empty());
}
