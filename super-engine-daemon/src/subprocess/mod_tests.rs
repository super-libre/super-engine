// SPDX-License-Identifier: GPL-3.0-only
//! What a subprocess backend is handed: the `POST /v1/load` body, the name
//! its instance runs under, its cache directory and its environment.

use super::*;
use super_engine_protocol::test_product::TEST;
use super_engine_spec::test_product::TestProduct;

type Manifest = super_engine_spec::manifest::Manifest<TestProduct>;

/// Backends released against the earlier `(name, provider)` model identity
/// validate `provider` on load and answer `400 invalid_model` when it is
/// absent. Dropping the key from the body makes every model of every such
/// backend unloadable, with no version gate that could soften it, so a
/// manifest that declares `provider` must still have it forwarded.
///
/// This is the test that fails if the compatibility echo is deleted before
/// those backends have rolled over.
#[test]
fn load_forwards_the_provider_a_manifest_declares() {
    let body = load_body("small", Some("local_small"), "cuda");
    assert_eq!(
        body.get("provider").and_then(serde_json::Value::as_str),
        Some("local_small"),
        "/v1/load dropped `provider`; backends validating it answer 400 invalid_model: {body}"
    );
    assert_eq!(
        body.get("name").and_then(serde_json::Value::as_str),
        Some("small")
    );
    assert_eq!(
        body.get("device").and_then(serde_json::Value::as_str),
        Some("cuda")
    );
}

/// The echo is driven by the manifest, not synthesized: a model that declares
/// no `provider` must not gain one, or a backend that *does* validate the key
/// would start rejecting a load it previously accepted.
#[test]
fn load_omits_provider_and_device_when_unset() {
    let body = load_body("small", None, "");
    assert!(
        body.get("provider").is_none(),
        "manifest declared no provider but the load body invented one: {body}"
    );
    assert!(
        body.get("device").is_none(),
        "empty device_pref sent: {body}"
    );
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "load body carries unexpected keys: {body}"
    );
}

/// `device` carries the resolved accelerator, so the daemon sends it only
/// when it has resolved one. A `cpu` preference always resolves — it is its
/// own accelerator — and must keep reaching the backend, since that is what
/// pins a load onto the CPU on a machine that has a GPU.
#[test]
fn load_sends_the_resolved_accelerator_and_never_the_bare_preference() {
    for accel in ["cpu", "cuda", "rocm", "vulkan", "metal"] {
        let body = load_body("small", None, accel);
        assert_eq!(
            body.get("device").and_then(serde_json::Value::as_str),
            Some(accel),
            "the resolved accelerator must reach the backend: {body}"
        );
    }
    // What a daemon resolves when it cannot name an accelerator — an install
    // with no record of one. `gpu` is the user's preference, and the contract
    // says this field is not that; an absent `device` means "auto-select",
    // which is the honest signal.
    let unresolved = load_body("small", None, "");
    assert!(
        unresolved.get("device").is_none(),
        "an unresolved accel must omit `device`, not send a preference: {unresolved}"
    );
}

/// End-to-end over the real parser: the value reaching the wire is the one
/// written in `backend.toml`. Guards the whole path, not just `load_body` —
/// a `ModelEntry::provider` that stopped deserializing would leave the unit
/// tests above passing while every real load lost the key.
#[test]
fn a_manifests_provider_reaches_the_load_body() {
    let toml = r#"
[backend]
source = "github.com/example/big"
name = "Big"
version = "0.1.0"
kind = "subprocess"
entrypoint = "big-backend"
contract = "v1"
description = "Test backend."

[[models]]
name = "big-flash"
provider = "local_big"
multilingual = true
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["cuda"]
"#;
    let manifest = Manifest::parse(toml).expect("fixture manifest parses");
    let model = &manifest.models[0];
    assert_eq!(model.provider.as_deref(), Some("local_big"));

    let body = load_body(&model.name, model.provider.as_deref(), "cuda");
    assert_eq!(
        body.get("provider").and_then(serde_json::Value::as_str),
        Some("local_big"),
        "the manifest's provider did not reach the load body: {body}"
    );
}

/// The instance key separates backends running at once. Keyed by model name
/// alone, a second spawn would unlink the first's live socket and clash on
/// its sandbox name.
#[test]
fn the_instance_key_distinguishes_backend_and_model() {
    let a = instance_key(
        Path::new("/backends/app.super-test.small"),
        "small-tiny",
        MAX_INSTANCE_KEY,
    );
    let b = instance_key(
        Path::new("/backends/app.super-test.small"),
        "cleanup",
        MAX_INSTANCE_KEY,
    );
    let c = instance_key(
        Path::new("/backends/com.example.small"),
        "small-tiny",
        MAX_INSTANCE_KEY,
    );

    assert_eq!(a, "app-super-test-small-small-tiny");
    assert_ne!(a, b, "two models in one backend must not share an instance");
    assert_ne!(
        a, c,
        "two backends serving the same model name must not share an instance"
    );
}

/// A backend `id` may be up to 255 bytes, and it names the install directory.
/// Left whole, the socket path would exceed `sun_path` and the bind would
/// fail; the key is bounded instead, and stays unique and deterministic.
///
/// Checked at both platforms' budgets, not just this host's: macOS leaves
/// roughly half the room Linux does, and a truncation that is only ever
/// exercised at the roomier bound is a bind failure waiting on the other
/// platform.
#[test]
fn an_over_long_instance_key_is_bounded_but_still_unique() {
    let long = format!("/backends/{}", "a".repeat(255));
    for max in [MIN_INSTANCE_KEY, 28, MAX_INSTANCE_KEY] {
        let a = instance_key(Path::new(&long), "small-tiny", max);
        let b = instance_key(Path::new(&long), "cleanup", max);

        assert!(a.len() <= max, "key must fit the socket path at max={max}");
        assert_ne!(
            a, b,
            "truncation must not collapse distinct models together at max={max}"
        );
        assert_eq!(
            a,
            instance_key(Path::new(&long), "small-tiny", max),
            "the same input must yield the same key on every spawn"
        );
    }
}

/// The budget is computed from the real socket directory, so a deeper
/// runtime path has to yield a shorter name — this is the whole reason the
/// bound is not a constant. macOS is the case that forced it: its per-user
/// runtime directory is around 70 bytes against Linux's 30.
#[test]
fn the_key_budget_shrinks_as_the_socket_directory_deepens() {
    let shallow = max_instance_key(Path::new("/run/user/1000/test/backends")).expect("fits");
    let deep = max_instance_key(Path::new(
        "/private/var/folders/xt/qnfxwqr938s_rd96dcghph3c0000gn/T/test/backends",
    ))
    .expect("fits");

    assert!(
        deep < shallow,
        "a deeper socket dir must leave less room: deep={deep} shallow={shallow}"
    );
    assert!(deep >= MIN_INSTANCE_KEY, "the macOS runtime dir must fit");

    // Every byte of the longest name the budget allows, plus the directory,
    // plus `.sock` and the terminator, must still fit `sun_path`.
    for (dir, budget) in [
        ("/run/user/1000/test/backends", shallow),
        (
            "/private/var/folders/xt/qnfxwqr938s_rd96dcghph3c0000gn/T/test/backends",
            deep,
        ),
    ] {
        let longest = format!("{dir}/{}.sock", "x".repeat(budget));
        assert!(
            longest.len() < super_engine_protocol::runtime::SUN_PATH_MAX,
            "{longest} is {} bytes, over sun_path",
            longest.len()
        );
    }
}

/// A runtime directory so deep that no usable name fits is reported as such,
/// rather than producing a name the kernel refuses with a bare `EINVAL` at
/// bind time.
#[test]
fn an_impossibly_deep_socket_directory_is_an_error() {
    let deep = format!(
        "/{}",
        "d".repeat(super_engine_protocol::runtime::SUN_PATH_MAX)
    );
    let err = max_instance_key(Path::new(&deep)).expect_err("must not claim a name fits");
    assert!(
        err.to_string().contains("too deep"),
        "the error should name the problem: {err}"
    );
}

/// The cache key comes from the backend directory's own name, so two
/// backends never share one — a shared cache would be a correctness bug
/// rather than a slow path, since `CubeCL`'s kernel database is keyed inside
/// the file by build and device, not by who wrote it.
#[test]
fn each_backend_gets_its_own_cache_dir() {
    let root = Path::new("/data/super-test/backends");
    let big = backend_cache_dir(&TEST, &root.join("app.super-test.big")).expect("named dir");
    let small = backend_cache_dir(&TEST, &root.join("app.super-test.small")).expect("named dir");
    assert_ne!(big, small);
    assert!(big.ends_with("backends/app-super-test-big"), "{big:?}");
    assert!(big.starts_with(super_engine_protocol::paths::cache_dir(&TEST)));
}

/// The directory name reaches the path through [`sanitize`], so a backend
/// directory that was somehow named with traversal cannot walk the cache
/// root. The installer will not produce such a name, but this path joins a
/// filesystem-derived string and is the wrong place to rely on that.
#[test]
fn a_traversing_directory_name_cannot_escape_the_cache_root() {
    let dir = Path::new("/data/super-test/backends/..");
    // `..` is a path component, not a name — Path::file_name refuses it.
    assert!(backend_cache_dir(&TEST, dir).is_err());

    let odd = backend_cache_dir(&TEST, Path::new("/data/x/a..b/")).expect("named dir");
    assert!(odd.starts_with(super_engine_protocol::paths::cache_dir(&TEST).join("backends")));
    assert!(odd.ends_with("a--b"), "{odd:?}");
}

/// Every cache the backend's libraries reach for must land in the one
/// writable directory, including the one that does not follow XDG.
///
/// The NVIDIA driver hardcodes `$HOME/.nv/ComputeCache`, which a read-only
/// `$HOME` makes readable and unwritable — so without `CUDA_CACHE_PATH` the
/// PTX-to-SASS translation is redone on every load and nothing says so. One
/// cold load of a 0.6B model was 1192 entries and 108 MB of work to redo.
#[test]
fn every_cache_lands_in_the_granted_directory() {
    let cache = Path::new("/cache/super-test/backends/app-super-test-big");
    let env = backend_env(
        &TEST,
        Path::new("/run/user/1000/test/backends/m.sock"),
        Path::new("/data/backends/app.super-test.big"),
        cache,
    );
    let get = |key: &str| env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    for key in ["SUPER_TEST_BACKEND_CACHE_DIR", "XDG_CACHE_HOME"] {
        assert_eq!(
            get(key),
            Some("/cache/super-test/backends/app-super-test-big"),
            "{key} must be the cache dir: {env:?}"
        );
    }
    assert_eq!(
        get("CUDA_CACHE_PATH"),
        Some("/cache/super-test/backends/app-super-test-big/nv"),
        "{env:?}"
    );
    // Bounded, so a few installed backends cannot each inherit the driver's
    // own gigabyte default.
    assert!(
        get("CUDA_CACHE_MAXSIZE").is_some(),
        "the driver cache must be capped: {env:?}"
    );
    // Every cache path handed over must be inside the one writable grant, or
    // it is a write the sandbox will refuse.
    for (key, value) in &env {
        assert!(
            !value.starts_with("/cache/") || value.starts_with(&cache.display().to_string()),
            "{key}={value} points outside the granted cache dir"
        );
    }
}

/// The contract's variables are named after the product, so two products'
/// backends each find their own.
#[test]
fn the_backend_reads_its_paths_from_the_products_variables() {
    let env = backend_env(
        &TEST,
        Path::new("/sock/m.sock"),
        Path::new("/data/b"),
        Path::new("/cache/b"),
    );
    assert!(env.contains(&(
        "SUPER_TEST_BACKEND_SOCKET".to_string(),
        "/sock/m.sock".to_string()
    )));
    assert!(env.contains(&("SUPER_TEST_BACKEND_DIR".to_string(), "/data/b".to_string())));
}

/// One instance, one live backend: a second hold on a held name is refused,
/// and the name is free again once the first hold is let go.
#[test]
fn an_instance_is_held_by_one_backend_at_a_time() {
    let name = format!("claim-test-{}", std::process::id());
    let first = Claim::take(&name).expect("a free name can be held");
    assert!(
        Claim::take(&name).is_none(),
        "a held name must not be handed out twice"
    );
    // Other instances are unaffected.
    let other = Claim::take(&format!("{name}-other")).expect("another name is free");
    drop(first);
    assert!(
        Claim::take(&name).is_some(),
        "a released name can be held again"
    );
    drop(other);
}
