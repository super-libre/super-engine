// SPDX-License-Identifier: GPL-3.0-only
//! Backends shipped as sandboxed native subprocesses (feature `subprocess`).
//!
//! [`SubprocessBackend`] spawns a backend's binary into a sandbox, waits for
//! it to answer on its pathname Unix socket, has it load one model, and then
//! carries the product's `/v1` requests to it. What those requests are — a
//! transcription, a synthesis — is the product's. This module knows only the
//! part of the contract every product shares: `/v1/ping`, `/v1/load`,
//! `/v1/status`, and the secret/option headers every request carries. The
//! model's files are provisioned before any of this, by the product (see
//! [`crate::download`]); the backend itself shares no code with the daemon.
//!
//! The sandbox is the one genuinely per-platform part: a hardened
//! `systemd-run --user` transient unit on Linux (`systemd`), a `sandbox-exec`
//! profile on macOS (`sandbox_exec`). Both expose the same handle — spawn,
//! label, logs, stop — so everything else here is the same code on both.
//! Their module docs set out what each confines, and where macOS is weaker.
//!
//! Everything named after the product — the unit names, the environment the
//! backend reads, the directories — comes from the [`ProductSpec`] passed in.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use log::info;
use super_engine_protocol::ProductSpec;
use super_engine_protocol::models::load_progress::LoadProgress;
use super_engine_spec::manifest::Device;
use tokio::net::UnixStream;

#[cfg(target_os = "macos")]
mod sandbox_exec;
#[cfg(target_os = "linux")]
mod systemd;

/// The platform's handle to a running, sandboxed backend.
#[cfg(target_os = "macos")]
use sandbox_exec::Sandboxed as Supervisor;
#[cfg(target_os = "linux")]
use systemd::Unit as Supervisor;

#[cfg(target_os = "macos")]
use sandbox_exec::spawn_sandboxed;
#[cfg(target_os = "linux")]
use systemd::spawn_sandboxed;

/// A running, sandboxed subprocess backend with one model loaded.
pub struct SubprocessBackend {
    socket: PathBuf,
    /// Handle to the sandbox the backend runs in. Dropping it stops the
    /// backend, which is why teardown needs no `Drop` impl of its own here.
    supervisor: Supervisor,
    /// Device label reported by the backend's `/v1/status` (e.g. `"cuda"`).
    device: String,
    /// The secret/option pairs injected on every `/v1` request, per the
    /// contract's request-header section. Resolved from the user's settings
    /// at spawn, and replaced in place by [`Self::set_context_headers`] when
    /// those settings change.
    ///
    /// Behind a lock rather than owned outright because the request paths
    /// hold only `&self`, and because the alternative to swapping it is
    /// reloading the model — which for a subprocess backend means tearing
    /// down the sandbox and re-provisioning the weights to change a header.
    context_headers: RwLock<Vec<(String, String)>>,
    /// This instance's hold on its name, released once the backend has
    /// stopped. Last, so a drop releases it only after the supervisor above
    /// has stopped the backend.
    claim: Option<Claim>,
}

/// The instances a live [`SubprocessBackend`] in this process holds.
static RUNNING: LazyLock<parking_lot::Mutex<HashSet<String>>> = LazyLock::new(Default::default);

/// A hold on one instance name, for as long as the backend behind it runs.
///
/// An instance's name is its socket path and its sandbox's name, both fixed by
/// the backend and the model, so a second spawn of a running instance cannot
/// get its own: it would unlink the live backend's socket, and then either be
/// refused its sandbox name — stranding the live backend, running but
/// unreachable — or stop the live backend to take the name, after which the
/// first handle's teardown, which stops by name, stops the replacement.
/// Refusing the second spawn outright, before it touches anything, is the one
/// answer that leaves every handle speaking for the backend it started.
///
/// This is only about backends a handle in this daemon still holds. A sandbox
/// left behind with no handle — a spawn cancelled halfway, a stop that did
/// not take — is the platform spawner's to clear, and it does.
struct Claim(String);

impl Claim {
    /// Hold `instance`, or `None` when a live backend already holds it.
    fn take(instance: &str) -> Option<Self> {
        RUNNING
            .lock()
            .insert(instance.to_string())
            .then(|| Self(instance.to_string()))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        RUNNING.lock().remove(&self.0);
    }
}

/// What [`SubprocessBackend::spawn`] starts, and the model it has it load.
pub struct Launch<'a> {
    /// The backend's install directory: `backend.toml`, the binary, and the
    /// model's files, already provisioned.
    pub backend_dir: &'a Path,
    /// The binary, relative to `backend_dir`: the manifest's `entrypoint`.
    pub entrypoint: &'a str,
    /// The model to load.
    pub model: &'a str,
    /// The model's declared `provider`, echoed on `/v1/load` (see
    /// [`load_body`]).
    pub provider: Option<&'a str>,
    /// The model's declared `supported_devices`. They decide whether the
    /// sandbox is granted the GPU.
    pub devices: &'a [Device],
    /// The resolved accelerator (`"cpu"`, `"cuda"`, `"rocm"`, `"metal"`,
    /// `"vulkan"`), or empty when none resolved, which leaves the backend to
    /// select for itself.
    pub device_pref: &'a str,
    /// The already-formed secret/option header pairs to inject on every
    /// request.
    pub context_headers: Vec<(String, String)>,
    /// Called with the backend's own report of its load each time it changes:
    /// its phase, its step, how far through the step it is. See
    /// [`LoadProgress`]. A daemon passes it on to its clients.
    pub on_load_progress: Option<&'a (dyn Fn(LoadProgress) + Send + Sync)>,
}

/// Everything a platform spawner needs to start one backend instance.
struct Sandbox<'a> {
    product: &'a ProductSpec,
    /// Names the instance: its socket, its sandbox, its sibling files. See
    /// [`instance_key`].
    instance: &'a str,
    binary: &'a Path,
    backend_dir: &'a Path,
    /// Writable: the backend binds its socket here.
    socket_dir: &'a Path,
    /// Writable and durable: see [`backend_cache_dir`].
    cache_dir: &'a Path,
    socket: &'a Path,
    /// Unread on macOS, where there are no GPU device nodes to withhold; see
    /// `sandbox_exec::spawn_sandboxed`.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    devices: &'a [Device],
}

impl SubprocessBackend {
    /// Spawn the sandboxed backend and have it load `launch.model`.
    ///
    /// The model's files must already be on disk under `launch.backend_dir`.
    ///
    /// # Errors
    /// Returns an error if this instance — this backend serving this model —
    /// is already loading or loaded in this daemon, if the socket or
    /// cache directory cannot be made, the binary is missing, the sandbox
    /// refuses to start, the backend does not answer within 30 seconds, or
    /// the load fails.
    pub async fn spawn(product: &ProductSpec, launch: Launch<'_>) -> Result<Self> {
        let Launch {
            backend_dir,
            entrypoint,
            model,
            provider,
            devices,
            device_pref,
            context_headers,
            on_load_progress,
        } = launch;

        // Socket under the runtime dir (pathname socket — survives
        // PrivateNetwork). Routed through the validated helper so it gets the
        // same traversal/prefix/length guards as the daemon's own sockets,
        // instead of a raw `$XDG_RUNTIME_DIR` join.
        //
        // Keyed by backend directory *and* model, not by model alone: a
        // daemon may run two backend instances at once, and two backends may
        // legitimately serve the same model name. Keyed by model alone, the
        // second spawn would unlink the live instance's socket and either
        // teardown would take out the other's.
        let socket_dir = super_engine_protocol::runtime::secure_runtime_path(product, "backends");
        std::fs::create_dir_all(&socket_dir)?;
        // Canonicalize now that the directory exists. The runtime dir is
        // reached through a symlink on macOS (`/var` -> `/private/var`), and
        // the eight bytes that adds are eight bytes of the `sun_path` budget
        // below — budgeting against the pre-canonical spelling would mint a
        // name the kernel then refuses to bind.
        let socket_dir = std::fs::canonicalize(&socket_dir).unwrap_or(socket_dir);

        let instance = instance_key(backend_dir, model, max_instance_key(&socket_dir)?);
        let socket = socket_dir.join(format!("{instance}.sock"));
        // Before anything is touched: the socket and the sandbox name are the
        // running instance's until it is released. "Loading or loaded",
        // because a second request for a model whose first load is still in
        // flight lands here too, and the answer then is to wait.
        let claim = Claim::take(&instance).with_context(|| {
            format!(
                "{model} is already loading or loaded as {instance}. Wait for it, or unload it \
                 before loading it again."
            )
        })?;

        let binary = backend_dir.join(entrypoint);
        anyhow::ensure!(
            binary.exists(),
            "backend binary not found: {}",
            binary.display()
        );

        // The one writable, durable path the sandbox grants. Created here
        // rather than by the backend: the sandbox's grant needs the directory
        // to exist when it spawns.
        let cache_dir = backend_cache_dir(product, backend_dir)?;
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("creating backend cache dir {}", cache_dir.display()))?;
        // The NVIDIA driver creates its own cache directory, but only where it
        // is allowed to: created here so it is in place before the backend
        // starts, exactly as the parent above is.
        std::fs::create_dir_all(cache_dir.join(NV_CACHE_DIR))
            .with_context(|| format!("creating driver cache dir under {}", cache_dir.display()))?;
        // Resolved for the same reason as the socket directory: macOS matches
        // a sandbox profile's paths against the resolved path, and a cache
        // under `/var/folders` is really under `/private/var/folders`.
        let cache_dir = std::fs::canonicalize(&cache_dir).unwrap_or(cache_dir);

        let supervisor = spawn_sandboxed(&Sandbox {
            product,
            instance: &instance,
            binary: &binary,
            backend_dir,
            socket_dir: &socket_dir,
            cache_dir: &cache_dir,
            socket: &socket,
            devices,
        })
        .await?;

        let mut backend = Self {
            socket,
            supervisor,
            device: "unknown".to_string(),
            context_headers: RwLock::new(context_headers),
            claim: Some(claim),
        };

        backend.wait_for_ping(Duration::from_secs(30)).await?;
        backend
            .load(model, provider, device_pref, on_load_progress)
            .await?;
        Ok(backend)
    }

    /// Poll `/v1/ping` until the backend is serving or the deadline passes.
    async fn wait_for_ping(&self, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok((200, _)) = self.request("GET", "/v1/ping", &[], Vec::new()).await {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "backend {} did not start within {timeout:?}.\n{}",
                    self.supervisor.label(),
                    self.logs()
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// `POST /v1/load` then poll `/v1/status` until `ready` (or `error`),
    /// capturing the device label the backend reports, and passing each change
    /// in the backend's own account of the load to `on_load_progress`.
    ///
    /// How long a load may take depends on whether the backend reports
    /// progress. One that does is held to [`STALL_TIMEOUT`] without its
    /// report moving, and to nothing else, so a slow first load on a slow
    /// card is not cut off while it is visibly working. One that does not
    /// gets [`LOAD_TIMEOUT`] in all.
    async fn load(
        &mut self,
        name: &str,
        provider: Option<&str>,
        device_pref: &str,
        on_load_progress: Option<&(dyn Fn(LoadProgress) + Send + Sync)>,
    ) -> Result<()> {
        let body = serde_json::to_vec(&load_body(name, provider, device_pref))?;
        let (status, resp) = self
            .request("POST", "/v1/load", &json_headers(), body)
            .await?;
        anyhow::ensure!(
            status == 202 || status == 200,
            "/v1/load returned {status}: {}",
            String::from_utf8_lossy(&resp)
        );

        let started = std::time::Instant::now();
        let mut watch = LoadWatch::new(started);
        loop {
            let (_, resp) = self
                .request("GET", "/v1/status", &[], Vec::new())
                .await
                .map_err(|e| {
                    self.load_failure(&format!("stopped answering while loading ({e:#})"))
                })?;
            let json: serde_json::Value = serde_json::from_slice(&resp)?;
            let state = json.get("state").and_then(|v| v.as_str());
            let now = std::time::Instant::now();
            if let Some(report) = watch.observe(LoadProgress::from_status(&json), now)
                && let Some(on_load_progress) = on_load_progress
            {
                on_load_progress(report);
            }
            match state {
                Some("ready") => {
                    let device = json.get("device").and_then(|v| v.as_str()).unwrap_or("?");
                    info!("backend ready (device={device})");
                    self.device = device.to_string();
                    return Ok(());
                }
                Some("error") => bail!(
                    "backend load failed: {}",
                    json.get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                ),
                _ => {}
            }
            if watch.stalled(now) {
                return Err(self.load_failure(&format!(
                    "stopped making progress: its load has not moved in {} seconds{}",
                    STALL_TIMEOUT.as_secs(),
                    watch.last_position()
                )));
            }
            if !watch.reports_progress() && now.duration_since(started) >= LOAD_TIMEOUT {
                return Err(self.load_failure(&format!(
                    "did not finish loading within {} minutes, and still reports `{}`",
                    LOAD_TIMEOUT.as_secs() / 60,
                    state.unwrap_or("no state")
                )));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// A load that ended without the backend saying why, with the backend's
    /// own recent output attached.
    ///
    /// A backend that reports `error` names its reason, and that is the whole
    /// story. This is for the other endings: the backend exited, or went on
    /// reporting `loading` after its load could no longer finish — a model
    /// thread that panicked, say. Its status says nothing either way, but its
    /// output usually holds the panic, and a bare "timed out" names neither.
    fn load_failure(&self, what: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "backend {} {what}. Its recent output:\n{}",
            self.label(),
            self.logs()
        )
    }

    /// Device label the backend reported at load time (e.g. `"cuda"`).
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// The instance's name, for log lines and error messages.
    #[must_use]
    pub fn label(&self) -> &str {
        self.supervisor.label()
    }

    /// Recent backend output, for a diagnostic.
    #[must_use]
    pub fn logs(&self) -> String {
        self.supervisor.logs()
    }

    /// Swap the injected secret/option pairs. The next `/v1` request carries
    /// them; one already in flight keeps the set it was built with.
    pub fn set_context_headers(&self, headers: Vec<(String, String)>) {
        *self
            .context_headers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = headers;
    }

    /// The secret/option pairs to inject on this request.
    ///
    /// Cloned rather than borrowed so the guard is dropped before the socket
    /// round-trip: these are a handful of short strings, and holding a read
    /// guard across a request would block a settings write for as long as the
    /// request runs.
    fn context_headers(&self) -> Vec<(String, String)> {
        self.context_headers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// One HTTP request over the backend's Unix socket, carrying `headers`
    /// plus the secret/option context every `/v1` request gets, with the
    /// response body read in full.
    ///
    /// # Errors
    /// Returns an error if the socket dial, the request, or reading the body
    /// fails. A non-2xx status is not an error here; it is returned.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>)> {
        let (resp, _connection) = self.send(method, path, headers, body).await?;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await?.to_bytes().to_vec();
        Ok((status, bytes))
    }

    /// [`Self::request`], with the response handed back as soon as its head
    /// arrives and its body left to stream.
    ///
    /// For a backend that writes its answer as it produces it — audio, say —
    /// so the daemon can use the start of it before the end exists. The
    /// [`Connection`] is what keeps the body arriving: hold it until the body
    /// is read.
    ///
    /// # Errors
    /// Returns an error if the socket dial or the request fails.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<(hyper::Response<hyper::body::Incoming>, Connection)> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connect {}", self.socket.display()))?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        // The connection task must keep running while the body streams — the
        // response is not complete when `send_request` resolves.
        let connection = Connection(tokio::spawn(async move {
            let _ = conn.await;
        }));

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "backend.local");
        let context = self.context_headers();
        for (k, v) in headers.iter().chain(&context) {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let req = builder.body(Full::new(Bytes::from(body)))?;

        let resp = sender.send_request(req).await?;
        Ok((resp, connection))
    }

    /// Stop the sandboxed backend, awaiting its exit, and remove the socket
    /// file.
    ///
    /// Call this before dropping the backend: it gives a real `.await`
    /// instead of blocking the runtime in `Drop`. After it returns, `Drop` is
    /// a no-op (the supervisor records that it already stopped) and stays for
    /// crash paths and tests.
    pub async fn shutdown(&mut self) {
        self.supervisor.stop().await;
        let _ = std::fs::remove_file(&self.socket);
        self.claim = None;
    }
}

impl Drop for SubprocessBackend {
    fn drop(&mut self) {
        // Stopping the backend is the supervisor's own `Drop`, which runs
        // when the field is dropped — synchronously, and idempotently after
        // an awaited `shutdown`. All that is left here is the socket file,
        // which neither supervisor knows about.
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// How long a load may take before the daemon gives up on it, when the
/// backend does not report its progress.
///
/// Generous on purpose: a backend that compiles its GPU kernels at runtime
/// does it during the load, which can take minutes on a cold cache, and
/// `ready` is what the daemon starts sending requests against. Without
/// progress, a stalled load and a slow one look the same, so this is the only
/// bound there is.
const LOAD_TIMEOUT: Duration = Duration::from_mins(10);

/// How long a load that reports progress may go without it moving.
///
/// The contract asks a backend to move `step` or `progress` at least once a
/// minute while it works, and this is twice that. Measured on a cold first
/// load (voxtral on an RTX 3090), the longest healthy gap was 3 s on CUDA and
/// 1.6 s on Vulkan when compiled kernels are counted with tuning results, and
/// 23 s when only tuning results are; a slower card stretches every gap.
const STALL_TIMEOUT: Duration = Duration::from_mins(2);

/// What a load's status polls have seen of the backend's own account of its
/// load, to tell a stalled load from a slow one.
struct LoadWatch {
    /// The last report, to tell a change from a repeat.
    last: Option<LoadProgress>,
    /// When the report last changed, or the load started.
    moved_at: std::time::Instant,
    /// Whether the backend has reported `progress` during this load. Only
    /// then does its standing still mean anything: a backend that never
    /// reports progress is not stalled for keeping quiet.
    reports_progress: bool,
}

impl LoadWatch {
    fn new(now: std::time::Instant) -> Self {
        Self {
            last: None,
            moved_at: now,
            reports_progress: false,
        }
    }

    /// Take one poll's report, returning it when it differs from the last.
    fn observe(
        &mut self,
        report: Option<LoadProgress>,
        now: std::time::Instant,
    ) -> Option<LoadProgress> {
        if report == self.last {
            return None;
        }
        self.moved_at = now;
        self.reports_progress |= report.as_ref().is_some_and(|r| r.progress.is_some());
        self.last.clone_from(&report);
        report
    }

    fn reports_progress(&self) -> bool {
        self.reports_progress
    }

    /// Whether the load has stopped moving: the backend reported progress,
    /// and then nothing it reports has changed for [`STALL_TIMEOUT`].
    fn stalled(&self, now: std::time::Instant) -> bool {
        self.reports_progress && now.duration_since(self.moved_at) >= STALL_TIMEOUT
    }

    /// Where the load was when it stopped, for the error: `" (building_kernels,
    /// at 45%)"`, or nothing when the backend said too little to name it.
    fn last_position(&self) -> String {
        let Some(last) = &self.last else {
            return String::new();
        };
        let step = last.step.as_deref().or(last.phase.as_deref());
        match (step, last.progress) {
            (Some(step), Some(p)) => format!(" ({step}, at {:.0}%)", p * 100.0),
            (Some(step), None) => format!(" ({step})"),
            (None, Some(p)) => format!(" (at {:.0}%)", p * 100.0),
            (None, None) => String::new(),
        }
    }
}

/// The task driving one connection to a backend. Dropping it closes the
/// connection.
pub struct Connection(tokio::task::JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The `content-type` header of a JSON request body.
#[must_use]
pub fn json_headers() -> Vec<(String, String)> {
    vec![("content-type".to_string(), "application/json".to_string())]
}

/// Build the `POST /v1/load` body. `name` is always present; `device` only
/// when the daemon resolved an accelerator to name, and `provider` only when
/// the model's manifest declares one.
///
/// `provider` is a compatibility echo (see [`ModelEntry::provider`]): backends
/// released against the earlier `(name, provider)` identity answer
/// `400 invalid_model` for a load body that omits it, so whatever the manifest
/// declares is forwarded verbatim.
///
/// [`ModelEntry::provider`]: super_engine_spec::manifest::ModelEntry::provider
fn load_body(name: &str, provider: Option<&str>, device_pref: &str) -> serde_json::Value {
    let mut load = serde_json::json!({ "name": name });
    if let Some(provider) = provider {
        load["provider"] = serde_json::json!(provider);
    }
    if !device_pref.is_empty() {
        load["device"] = serde_json::json!(device_pref);
    }
    load
}

/// Stop backends left behind by a previous daemon run.
///
/// Call it at daemon startup, as defense against a previous daemon that
/// exited without shutting its backends down (SIGKILL, a panic,
/// `std::process::exit` skipping `Drop`). Those backends keep a model
/// resident — gigabytes of VRAM — and nothing else will reach them. What
/// "left behind" means, and how one is found again, is per-platform: see
/// `systemd::cleanup_orphan_units` and `sandbox_exec::sweep_orphans`.
pub async fn cleanup_orphans(product: &ProductSpec) {
    #[cfg(target_os = "linux")]
    systemd::cleanup_orphan_units(product).await;
    #[cfg(target_os = "macos")]
    sandbox_exec::sweep_orphans(&super_engine_protocol::runtime::secure_runtime_path(
        product, "backends",
    ))
    .await;
}

/// Where the NVIDIA driver keeps its PTX-to-SASS translations, relative to the
/// cache directory the sandbox grants.
const NV_CACHE_DIR: &str = "nv";

/// How large that cache may grow, in bytes.
///
/// Set rather than left to the driver's own default, which is around a
/// gigabyte: the cache is per backend, so the default would be inherited once
/// per installed backend and a few of them would quietly cost several
/// gigabytes. 512 MiB is sized from measurement — one cold load of a 0.6B model
/// wrote 1192 entries totalling 108 MB — so it holds several models before the
/// driver starts evicting the least recently used.
const NV_CACHE_MAXSIZE: u64 = 512 * 1024 * 1024;

/// The environment the backend is spawned with.
///
/// Split out and tested because every line here is silent when it goes
/// missing. The backend keeps working and merely pays for something on every
/// load, which is exactly the kind of regression that survives review.
///
/// The cache directory is handed over three ways, because three different
/// consumers look for it three different ways:
///
/// - `<PREFIX>_BACKEND_CACHE_DIR`, for a backend that reads the contract.
/// - `XDG_CACHE_HOME`, for a library that resolves its own cache the XDG way,
///   so it lands here rather than under the read-only `$HOME`.
/// - `CUDA_CACHE_PATH`, because the NVIDIA driver does neither: it hardcodes
///   `$HOME/.nv/ComputeCache` and ignores XDG, which makes it the one consumer
///   the line above misses. A read-only `$HOME` then lets it *read* a cache
///   it can never write, so on any machine that has not run this backend
///   outside the sandbox the PTX-to-SASS translation is redone on every load,
///   forever. That is below `CubeCL`'s own cache and invisible to it. Inert
///   where there is no NVIDIA driver.
///
/// Per backend rather than shared between them, deliberately. Sharing would
/// only pay between backends pinned to the same `CubeCL` revision, since the
/// driver keys on the PTX itself, and it would make one sandbox's writes
/// readable as executable GPU code by another — which is the isolation the
/// per-backend cache directory exists to provide.
fn backend_env(
    product: &ProductSpec,
    socket: &Path,
    backend_dir: &Path,
    cache_dir: &Path,
) -> Vec<(String, String)> {
    let path = |p: &Path| p.display().to_string();
    vec![
        (product.env("BACKEND_SOCKET"), path(socket)),
        (product.env("BACKEND_DIR"), path(backend_dir)),
        (product.env("BACKEND_CACHE_DIR"), path(cache_dir)),
        ("XDG_CACHE_HOME".to_string(), path(cache_dir)),
        (
            "CUDA_CACHE_PATH".to_string(),
            path(&cache_dir.join(NV_CACHE_DIR)),
        ),
        (
            "CUDA_CACHE_MAXSIZE".to_string(),
            NV_CACHE_MAXSIZE.to_string(),
        ),
        ("RUST_LOG".to_string(), "info".to_string()),
    ]
}

/// The writable, durable cache directory granted to a backend's sandbox.
///
/// Everything else the sandbox exposes is read-only or discarded: the backend
/// directory and `$HOME` are read-only, and the writable scratch directory
/// dies with the backend. A backend with nothing to keep never notices. One
/// that compiles its GPU kernels at runtime does: `CubeCL` (the Burn backends)
/// spends about twenty seconds compiling a few hundred kernels, caches them
/// keyed by build and device, and without a durable home pays that on *every*
/// load rather than once per install.
///
/// Keyed on the backend directory's name — the backend id the installer names
/// it after — so backends never share a cache, and an in-place upgrade keeps
/// the one it warmed. [`sanitize`] is what keeps a directory name from
/// steering the path anywhere else.
fn backend_cache_dir(product: &ProductSpec, backend_dir: &Path) -> Result<PathBuf> {
    let key = backend_dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("backend directory has no name to key its cache on")?;
    Ok(super_engine_protocol::paths::cache_dir(product)
        .join("backends")
        .join(sanitize(key)))
}

/// Hex digits in the disambiguating hash appended to a truncated key.
const DIGEST_LEN: usize = 16;

/// Shortest instance key worth minting: a one-character head, a separator,
/// and the full digest. Below this the key is all hash and the truncation
/// carries no hint of what it names, so a socket directory this deep is
/// reported as an error rather than papered over.
const MIN_INSTANCE_KEY: usize = DIGEST_LEN + 2;

/// Upper bound on an instance key regardless of how much room the socket
/// path leaves.
///
/// Keys are almost always far shorter; this bounds the tail case, since a
/// backend `id` — which names the install directory — may be up to 255 bytes
/// on its own, and a 255-byte file name is unreadable in a log line whether
/// or not it fits.
const MAX_INSTANCE_KEY: usize = 64;

/// Longest instance key that still leaves room for the socket path in
/// `socket_dir`.
///
/// A pathname Unix socket must fit in `sun_path`, terminator included — 108
/// bytes on Linux, **104 on macOS**. Computed from the real directory rather
/// than assumed, because the room left over differs by platform by more than
/// those four bytes: Linux binds under `/run/user/<uid>/<short name>/backends/`,
/// about 30 bytes, while the macOS per-user runtime directory is
/// `/private/var/folders/<xx>/<28-char hash>/T/<short name>/backends/` — around
/// 70, leaving less than half as much for the name.
///
/// # Errors
/// When the directory is so deep that not even [`MIN_INSTANCE_KEY`] fits.
/// That is a misconfigured runtime directory, and failing here names it,
/// where binding would fail later with `EINVAL` and name nothing.
fn max_instance_key(socket_dir: &Path) -> Result<usize> {
    const SUFFIX: usize = ".sock".len();
    const SEPARATOR: usize = 1; // the `/` between the directory and the name
    let budget = super_engine_protocol::runtime::SUN_PATH_MAX
        .saturating_sub(socket_dir.as_os_str().len() + SEPARATOR + SUFFIX + 1);
    if budget < MIN_INSTANCE_KEY {
        bail!(
            "backend socket directory {} is too deep: it leaves {budget} bytes for a socket \
             name, and the shortest usable one is {MIN_INSTANCE_KEY}",
            socket_dir.display()
        );
    }
    Ok(budget.min(MAX_INSTANCE_KEY))
}

/// The name that identifies one running backend instance — its socket file and
/// its sandbox. Derived from the backend's install directory and the model
/// it serves, so two instances running at once never collide, including when
/// two backends serve the same model name.
///
/// A key over `max_len` is truncated with a hash of the full value appended,
/// so an over-long backend id yields a short name that is still unique and
/// still the same on every spawn — rather than a socket path the kernel
/// refuses to bind. `max_len` comes from [`max_instance_key`].
fn instance_key(backend_dir: &Path, model_name: &str, max_len: usize) -> String {
    let dir = backend_dir
        .file_name()
        .map_or_else(String::new, |n| sanitize(&n.to_string_lossy()));
    let key = format!("{dir}-{}", sanitize(model_name));
    if key.len() <= max_len {
        return key;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&key, &mut hasher);
    let digest = format!("{:0DIGEST_LEN$x}", std::hash::Hasher::finish(&hasher));
    // `max_len` total: the truncated head, a separator, and the digest.
    let head = &key[..max_len - digest.len() - 1];
    format!("{head}-{digest}")
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
