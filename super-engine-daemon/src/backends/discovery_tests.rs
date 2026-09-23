// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::fs;

use super_engine_spec::test_product::{Role, TestProduct};

type Backend = DiscoveredBackend<TestProduct>;
type Definition = ModelDefinition<super_engine_spec::test_product::Model>;

fn discover(dir: &Path) -> (Vec<Backend>, Vec<Backend>) {
    super::discover::<TestProduct>(dir)
}

/// Write `toml` as `root/<dir>/backend.toml`.
fn write_manifest(root: &Path, dir: &str, toml: &str) -> PathBuf {
    let d = root.join(dir);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("backend.toml"), toml).unwrap();
    d
}

/// A WASM backend (API-shaped) and a subprocess backend (local-shaped) are
/// both discovered, and their models resolve by `(name, source)`.
#[test]
fn discovers_wasm_and_subprocess_backends() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(
        root.path(),
        "openai",
        r#"
[backend]
source = "github.com/x/openai"
name = "OpenAI"
version = "0.1.0"
kind = "wasm"
entrypoint = "openai.wasm"
contract = "v1"
description = "Test backend."

[network]
allowed_hosts = ["api.openai.com"]

[[secrets]]
name = "OPENAI_API_KEY"
description = "OpenAI API key."
required = true

[[options]]
name = "base_url"
description = "Base URL."
type = "string"

[[models]]
name = "whisper-1"
multilingual = true
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["none"]
"#,
    );
    write_manifest(
        root.path(),
        "local",
        r#"
[backend]
source = "github.com/x/local"
name = "Local"
version = "0.1.0"
kind = "subprocess"
entrypoint = "local-backend"
contract = "v1"
description = "Test backend."

[[models]]
name = "local-mini"
multilingual = true
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["cpu", "cuda"]
estimated_vram_bytes = 8589934592
processing_interval_ms = 1500
"#,
    );

    let (backends, losers) = discover(root.path());
    assert_eq!(backends.len(), 2, "expected two backends, got {backends:?}");
    assert!(losers.is_empty(), "distinct sources are never duplicates");

    // Identity + secrets/options carried through.
    let oai = backends
        .iter()
        .find(|b| b.source == "github.com/x/openai")
        .expect("openai backend");
    assert_eq!(oai.kind, "wasm");
    assert_eq!(oai.entrypoint, "openai.wasm");
    assert_eq!(oai.description, "Test backend.");
    assert_eq!(oai.allowed_hosts, vec!["api.openai.com".to_string()]);
    assert_eq!(oai.secrets.len(), 1);
    assert!(oai.secrets[0].required);
    assert_eq!(oai.options.len(), 1);
    // Carried from the manifest: for a backend the registry does not list, this
    // is the only version there is, so dropping it here would leave the catalog
    // unable to say what is installed.
    assert_eq!(oai.version, "0.1.0");

    // find_model resolves the pair against the declaring backend.
    let (b, def) =
        find_model(&backends, "whisper-1", "github.com/x/openai").expect("resolve whisper-1");
    assert_eq!(b.kind, "wasm");
    assert_eq!(def.source, "github.com/x/openai");
    assert_eq!(
        def.supported_devices,
        vec![Device::None],
        "online model carries its declared supported_devices"
    );
    assert!(def.is_online());
    // The default for a model that does not say.
    assert_eq!(def.processing_interval, Duration::from_secs(2));

    let (_, local) =
        find_model(&backends, "local-mini", "github.com/x/local").expect("resolve local-mini");
    assert_eq!(local.source, "github.com/x/local");
    assert_eq!(local.estimated_vram_bytes, 8_589_934_592);
    assert_eq!(local.processing_interval, Duration::from_millis(1500));
    assert_eq!(
        local.supported_devices,
        vec![Device::Cpu, Device::Gpu],
        "local model carries its declared supported_devices"
    );
    assert!(!local.is_online());

    // list_models flattens both.
    let listed = list_models(&backends);
    assert_eq!(listed.len(), 2);
    assert!(
        listed
            .iter()
            .any(|(n, s)| n == "whisper-1" && s == "github.com/x/openai")
    );
}

/// The product's own `[[models]]` keys ride along on the definition as the
/// manifest declared them, and its `[capabilities]` keys on the backend.
#[test]
fn the_products_own_keys_are_carried() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(
        root.path(),
        "cloud",
        r#"
[backend]
id = "app.test.cloud"
source = "github.com/x/cloud"
name = "Cloud"
version = "0.1.0"
kind = "wasm"
entrypoint = "cloud.wasm"
contract = "v2"
description = "Test backend."

[capabilities]
websocket = true
context = true

[[models]]
name = "fast"
multilingual = true
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["none"]
realtime = true
force_preview_support = true
role = "post_processor"

[[models]]
name = "plain"
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["none"]
"#,
    );

    let (backends, _) = discover(root.path());
    let (b, fast) = find_model(&backends, "fast", "github.com/x/cloud").expect("resolves");
    assert!(b.capabilities.websocket);
    assert!(b.capabilities.product.context);
    assert!(fast.realtime);
    assert!(
        fast.product.force_preview_support,
        "the declared opt-in is carried"
    );
    assert_eq!(fast.product.role, Role::PostProcessor);

    let (_, plain) = find_model(&backends, "plain", "github.com/x/cloud").expect("resolves");
    assert!(!plain.realtime);
    assert!(!plain.product.force_preview_support);
    assert_eq!(plain.product.role, Role::Transcription);
}

/// A backend already on disk is read as installed: a field a newer contract
/// requires does not drop a backend that installed cleanly before the rule
/// existed.
#[test]
fn an_installed_backend_is_not_held_to_the_new_manifest_rules() {
    let root = tempfile::tempdir().unwrap();
    // `role` needs contract v2, which this manifest does not declare.
    let dir = write_manifest(
        root.path(),
        "old",
        r#"
[backend]
source = "github.com/x/old"
name = "Old"
version = "0.1.0"
kind = "wasm"
entrypoint = "old.wasm"
contract = "v1"
description = "Test backend."

[[models]]
name = "m"
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["none"]
role = "transcription"
"#,
    );
    assert!(
        Manifest::<TestProduct>::load(&dir).is_err(),
        "the premise: a new manifest like this is refused"
    );

    let (backends, _) = discover(root.path());
    assert_eq!(backends.len(), 1, "the installed backend is still served");
    assert_eq!(
        installed_version::<TestProduct>(&dir).as_deref(),
        Some("0.1.0")
    );
}

/// A subdirectory without a parseable `backend.toml` is skipped, not fatal.
#[test]
fn skips_invalid_backend_dirs() {
    let root = tempfile::tempdir().unwrap();
    let junk = root.path().join("not-a-backend");
    fs::create_dir_all(&junk).unwrap();
    fs::write(junk.join("readme.txt"), "hi").unwrap();
    write_manifest(root.path(), "broken", "this is not valid toml = =\n");

    assert!(discover(root.path()).0.is_empty());
}

#[test]
fn missing_dir_is_empty() {
    let root = tempfile::tempdir().unwrap();
    assert!(discover(&root.path().join("does-not-exist")).0.is_empty());
}

/// A single-model wasm manifest whose model declares `devices` (a TOML
/// fragment, or nothing when `None`).
fn manifest_with_devices(devices: Option<&str>) -> String {
    let line = devices.map_or(String::new(), |d| format!("supported_devices = {d}"));
    format!(
        r#"
[backend]
source = "github.com/x/openai"
name = "OpenAI"
version = "0.1.0"
kind = "wasm"
entrypoint = "openai.wasm"
contract = "v1"
description = "Test backend."

[[models]]
name = "whisper-1"
multilingual = true
primary_language = "en"
supported_languages = ["en"]
{line}
"#
    )
}

/// A backend whose manifest omits `supported_devices` on any model is
/// rejected at discovery — the field is required.
#[test]
fn missing_supported_devices_skips_backend() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(root.path(), "openai", &manifest_with_devices(None));
    assert!(
        discover(root.path()).0.is_empty(),
        "a manifest without supported_devices must be rejected"
    );
}

/// A backend whose manifest has an explicit empty `supported_devices = []` on a
/// model is rejected at discovery — the empty-list bail in
/// `validate_supported_devices` must be reached even when the field is present.
#[test]
fn empty_supported_devices_skips_backend() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(root.path(), "openai", &manifest_with_devices(Some("[]")));
    assert!(
        discover(root.path()).0.is_empty(),
        "a manifest with supported_devices = [] must be rejected"
    );
}

/// Unknown device strings (`xpu`) cause the whole backend to be skipped.
#[test]
fn unknown_device_skips_backend() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(
        root.path(),
        "openai",
        &manifest_with_devices(Some(r#"["xpu"]"#)),
    );
    assert!(discover(root.path()).0.is_empty());
}

/// `none` (online sentinel) mixed with a local device is rejected — they
/// contradict each other.
#[test]
fn none_mixed_with_local_device_skips_backend() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(
        root.path(),
        "openai",
        &manifest_with_devices(Some(r#"["none", "cpu"]"#)),
    );
    assert!(discover(root.path()).0.is_empty());
}

/// A device declared twice is served once, in declaration order.
#[test]
fn a_repeated_device_is_listed_once() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(
        root.path(),
        "openai",
        &manifest_with_devices(Some(r#"["cuda", "cpu", "cuda"]"#)),
    );
    let (backends, _) = discover(root.path());
    assert_eq!(
        backends[0].models[0].supported_devices,
        vec![Device::Gpu, Device::Cpu]
    );
}

/// A backend at `dir`, with no models, for the selection tests.
fn at(dir: &str, source: &str, version: &str, id: Option<&str>) -> Backend {
    Backend {
        description: String::new(),
        dir: PathBuf::from("/backends").join(dir),
        source: source.to_string(),
        name: dir.to_string(),
        version: version.to_string(),
        kind: "wasm".to_string(),
        entrypoint: "x.wasm".to_string(),
        allowed_hosts: Vec::new(),
        secrets: Vec::new(),
        options: Vec::new(),
        capabilities: Capabilities::default(),
        models: Vec::new(),
        id: id.map(str::to_string),
    }
}

/// `dir_name` returns the final path component — the relative install dir a
/// daemon persists as its active backend. A trailing slash and a root-only
/// path both return `None` (no usable handle).
#[test]
fn dir_name_returns_final_component() {
    let mut b = at("openai", "github.com/x/openai", "1.0.0", None);
    assert_eq!(dir_name(&b).as_deref(), Some("openai"));

    b.dir = PathBuf::from("/home/u/.local/share/super-x/backends/mistral/");
    assert_eq!(dir_name(&b).as_deref(), Some("mistral"));

    b.dir = PathBuf::from("/");
    assert!(
        dir_name(&b).is_none(),
        "a root path has no file_name → None"
    );
}

/// Write a minimal single-model wasm backend into `root/<dir>` with the
/// given `source`. Enough for discovery to succeed.
fn write_backend(root: &Path, dir: &str, source: &str, name: &str) {
    write_manifest(
        root,
        dir,
        &format!(
            r#"
[backend]
source = "{source}"
name = "{name}"
version = "0.1.0"
kind = "wasm"
entrypoint = "{dir}.wasm"
contract = "v1"
description = "Test backend."

[[models]]
name = "{dir}-base"
multilingual = true
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["none"]
"#
        ),
    );
}

/// Backends from one monorepo each declare a distinct source namespaced
/// under the shared repo, so resolving the active backend by source —
/// `find(|b| b.source == source).and_then(dir_name)` — lands on the
/// requested backend. This is the regression test for the bug where all
/// three shared one source and selecting one activated another.
#[test]
fn distinct_sources_resolve_to_the_right_backend() {
    let root = tempfile::tempdir().unwrap();
    for (dir, name) in [
        ("openai", "OpenAI"),
        ("mistral", "Mistral"),
        ("local", "Local"),
    ] {
        write_backend(
            root.path(),
            dir,
            &format!("github.com/x/monorepo/{dir}"),
            name,
        );
    }

    let (backends, losers) = discover(root.path());
    assert_eq!(backends.len(), 3);
    assert!(
        losers.is_empty(),
        "three distinct sources are never duplicates"
    );

    for want_dir in ["openai", "mistral", "local"] {
        let source = format!("github.com/x/monorepo/{want_dir}");
        let resolved = backends
            .iter()
            .find(|b| b.source == source)
            .and_then(dir_name);
        assert_eq!(
            resolved.as_deref(),
            Some(want_dir),
            "source {source} should resolve to dir {want_dir}"
        );
    }
}

/// Two backends sharing a source is a misconfiguration: discovery keeps one
/// deterministic winner and reports the rest as duplicates for reconciliation,
/// so resolution is never ambiguous.
#[test]
fn duplicate_sources_are_deduplicated() {
    let root = tempfile::tempdir().unwrap();
    // Same source, same version, neither id-named — the tie falls to the
    // lexicographically first directory name.
    write_backend(root.path(), "aaa", "github.com/x/shared", "First");
    write_backend(root.path(), "bbb", "github.com/x/shared", "Second");

    let (backends, losers) = discover(root.path());
    assert_eq!(
        backends.len(),
        1,
        "duplicate source must be collapsed to one"
    );
    assert_eq!(losers.len(), 1, "the duplicate is reported, not dropped");
    assert!(losers[0].dir.ends_with("bbb"));

    // Exactly one backend resolves for the shared source — no ambiguity.
    let matches: Vec<_> = backends
        .iter()
        .filter(|b| b.source == "github.com/x/shared")
        .collect();
    assert_eq!(matches.len(), 1);
}

/// At equal version and with neither candidate id-named, `dedup_sources`
/// falls back to the lexicographically first directory name, so the result is
/// stable across runs.
#[test]
fn dedup_sources_falls_back_to_lexicographic_order() {
    let input = vec![
        at("a", "src-1", "1.0.0", None),
        at("b", "src-2", "1.0.0", None),
        at("c", "src-1", "1.0.0", None), // dup of a
        at("d", "src-3", "1.0.0", None),
    ];
    let (winners, losers) = dedup_sources(input);
    let dirs: Vec<_> = winners.iter().filter_map(dir_name).collect();
    assert_eq!(dirs, vec!["a", "b", "d"]);
    assert_eq!(losers.len(), 1);
    assert!(losers[0].dir.ends_with("c"));
}

/// The regression: `find_model` used to treat an empty `source` as "any
/// backend" and return the first one serving the name. Scan order is
/// `read_dir` order, and a daemon *persists* the backend it resolves — so it
/// could bind a model to a different engine between runs and keep that choice
/// across restarts. Resolving an omitted `source` belongs to the caller
/// (against the active backend); here it matches nothing.
#[test]
fn an_empty_source_resolves_nothing() {
    fn serving(dir: &str, source: &str, model: &str) -> Backend {
        let mut b = at(dir, source, "1.0.0", None);
        b.models = vec![Definition {
            name: model.to_string(),
            source: source.to_string(),
            is_multilingual: true,
            primary_language: "en".to_string(),
            supported_languages: vec!["en".to_string()],
            estimated_vram_bytes: 0,
            processing_interval: Duration::from_secs(1),
            supported_devices: vec![Device::Cpu],
            realtime: false,
            provider: None,
            product: super_engine_spec::test_product::Model {
                force_preview_support: false,
                role: Role::Transcription,
            },
        }];
        b
    }

    // Two backends serving the same model name — the case the contract calls
    // out as supported, and the one that made scan order load-bearing.
    let backends = vec![
        serving("zeta", "github.com/other/zeta", "whisper-tiny"),
        serving("whisper", "github.com/x/whisper", "whisper-tiny"),
    ];

    assert!(
        find_model(&backends, "whisper-tiny", "").is_none(),
        "an empty source must not silently bind to a scan-order winner"
    );

    // Each concrete source resolves to its own backend, regardless of order.
    for (source, dir) in [
        ("github.com/other/zeta", "zeta"),
        ("github.com/x/whisper", "whisper"),
    ] {
        let (b, def) = find_model(&backends, "whisper-tiny", source)
            .unwrap_or_else(|| panic!("resolve whisper-tiny from {source}"));
        assert_eq!(dir_name(b).as_deref(), Some(dir));
        assert_eq!(def.source, source);
    }

    // A source that serves a different name is still a miss.
    assert!(find_model(&backends, "whisper-large", "github.com/other/zeta").is_none());
}

/// A manifest that declares a `default` for `base_url` is wrong — that value
/// authorizes egress the sandbox would otherwise refuse, and only the user may
/// ask for it. The backend still loads, with the option intact and the value
/// dropped, so an author's mistake costs the user a setting rather than the
/// whole backend. (The registry indexer refuses to publish such a release, so
/// this is the sideloaded/local case.)
#[test]
fn discovery_drops_a_base_url_default_and_keeps_the_backend() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(
        root.path(),
        "openai",
        r#"
[backend]
source = "github.com/x/openai"
name = "OpenAI"
version = "0.1.0"
kind = "wasm"
entrypoint = "openai.wasm"
contract = "v1"
description = "Test backend."

[[options]]
name = "base_url"
description = "Base URL."
type = "string"
default = "http://127.0.0.1:11434"

[[options]]
name = "region"
description = "Region."
type = "string"
default = "us-east-1"

[[models]]
name = "whisper-1"
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["none"]
"#,
    );

    let (backends, _) = discover(root.path());
    assert_eq!(
        backends.len(),
        1,
        "the backend must still load: {backends:?}"
    );
    let opts = &backends[0].options;
    assert_eq!(opts[0].name, "base_url");
    assert!(
        opts[0].default.is_none(),
        "the manifest's base_url value must not survive discovery"
    );
    // Only that option is touched; every other default is the author's to set.
    assert_eq!(opts[1].name, "region");
    assert!(opts[1].default.is_some());
}

/// Version outranks the id-named directory. A backend updated in place
/// before migration existed sits at the repo-named directory on the newer
/// version; preferring the id-named one would delete the newer install and
/// silently downgrade the user.
#[test]
fn the_higher_version_wins_even_against_the_id_named_dir() {
    let (winners, losers) = dedup_sources(vec![
        at(
            "app.super-x.voxtral",
            "github.com/x/v",
            "0.1.0",
            Some("app.super-x.voxtral"),
        ),
        at(
            "super-x-voxtral",
            "github.com/x/v",
            "0.1.1",
            Some("app.super-x.voxtral"),
        ),
    ]);
    assert_eq!(winners.len(), 1);
    assert!(winners[0].dir.ends_with("super-x-voxtral"));
    assert_eq!(losers.len(), 1);
}

#[test]
fn the_id_named_dir_wins_at_equal_versions() {
    let (winners, losers) = dedup_sources(vec![
        at(
            "super-x-voxtral",
            "github.com/x/v",
            "0.1.1",
            Some("app.super-x.voxtral"),
        ),
        at(
            "app.super-x.voxtral",
            "github.com/x/v",
            "0.1.1",
            Some("app.super-x.voxtral"),
        ),
    ]);
    assert!(winners[0].dir.ends_with("app.super-x.voxtral"));
    assert_eq!(losers.len(), 1);
}

#[test]
fn distinct_sources_are_never_duplicates() {
    let (winners, losers) = dedup_sources(vec![
        at("a", "github.com/x/a", "1.0.0", None),
        at("b", "github.com/x/b", "1.0.0", None),
    ]);
    assert_eq!(winners.len(), 2);
    assert!(losers.is_empty());
}

#[test]
fn the_default_backends_dir_is_under_the_products_data_dir() {
    let product = &super_engine_protocol::test_product::TEST;
    assert_eq!(
        default_backends_dir(product),
        super_engine_protocol::paths::data_dir(product).join("backends")
    );
}
