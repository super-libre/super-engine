// SPDX-License-Identifier: GPL-3.0-only
//! systemd `--user` transient-unit lifecycle for subprocess backends: spawning
//! the hardened sandbox unit, sweeping orphaned units left by a prior daemon
//! run, and the sandbox directives (shared with the enforcement test so they
//! stay in lock-step).

use std::path::Path;

use anyhow::{Context, Result, bail};
use log::{info, warn};
use super_engine_protocol::ProductSpec;
use super_engine_spec::manifest::Device;

use super::{Sandbox, backend_env};

/// The prefix every backend unit's name starts with, `<slug>-backend-`.
///
/// Load-bearing: it is what [`cleanup_orphan_units`] sweeps by, so it is made
/// here, next to the sweep, rather than by any caller.
fn unit_prefix(product: &ProductSpec) -> String {
    format!("{}-backend-", product.slug)
}

/// Stop leftover `<slug>-backend-*` `--user` transient units whose daemon is
/// gone.
///
/// **Only the dead ones.** Sweeping every matching unit is correct exactly
/// when no other daemon is running and destructive whenever one is: a second
/// daemon starting — a test that spawns its own, a restart racing the old
/// process, two checkouts — pulled the backend out from under a daemon that
/// was happily serving, leaving it reporting a model loaded with nothing
/// behind the socket, and the reloaded backend fighting the first for the GPU.
/// The unit name ends in the PID of the daemon that spawned it precisely so the
/// two can be told apart; [`is_orphaned_unit`] reads it.
pub(super) async fn cleanup_orphan_units(product: &ProductSpec) {
    let prefix = unit_prefix(product);
    // `systemctl --user list-units` is the safest enumerator: it includes
    // both active and failed transient units (so we can stop them all in
    // one shot) and is silent when nothing matches.
    let listing = match tokio::process::Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "--all",
            "--type=service",
            "--no-legend",
            "--plain",
            &format!("{prefix}*"),
        ])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            warn!(
                "list-units for orphan sweep returned {}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr),
            );
            return;
        }
        Err(e) => {
            warn!("could not enumerate user units for orphan sweep: {e}");
            return;
        }
    };
    let listing = String::from_utf8_lossy(&listing);
    let daemon = product.daemon_binary();
    let units: Vec<String> = listing
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .filter(|u| u.starts_with(&prefix))
        .filter(|u| is_orphaned_unit(u, |pid| daemon_is_alive(&daemon, pid)))
        .collect();
    if units.is_empty() {
        return;
    }
    info!(
        "Sweeping {} orphaned backend unit(s) from a previous run",
        units.len()
    );
    for unit in units {
        match tokio::process::Command::new("systemctl")
            .args(["--user", "stop", &unit])
            .status()
            .await
        {
            Ok(s) if s.success() => info!("stopped orphan {unit}"),
            Ok(s) => warn!("systemctl --user stop {unit} exited with {s}"),
            Err(e) => warn!("failed to stop orphan {unit}: {e}"),
        }
    }
}

/// Whether `unit` was left behind by a daemon that is no longer running.
///
/// The name is `<slug>-backend-<instance>-<pid>[.service]`, and the instance
/// part may itself contain dashes, so the PID is the segment after the *last*
/// one. `alive` answers whether that PID is a running daemon.
///
/// Unparseable names and live owners are both left alone. That asymmetry is
/// deliberate: a unit wrongly swept takes a working daemon's backend with it,
/// while a unit wrongly kept costs memory until the next restart — one is a
/// broken machine, the other is untidy.
fn is_orphaned_unit(unit: &str, alive: impl Fn(u32) -> bool) -> bool {
    let name = unit.strip_suffix(".service").unwrap_or(unit);
    let Some((_, pid)) = name.rsplit_once('-') else {
        return false;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return false;
    };
    // Our own units are not orphans either: this runs before any of them
    // exists, but a retry later in the process's life must not sweep them.
    pid != std::process::id() && !alive(pid)
}

/// The longest process name the kernel keeps in `/proc/<pid>/comm`: the
/// 16-byte `TASK_COMM_LEN`, less its terminator.
const COMM_MAX: usize = 15;

/// Whether `pid` is a live daemon whose binary is named `daemon`.
///
/// Checks the name as well as existence, so a recycled PID now belonging to
/// something unrelated does not make a genuine orphan look owned.
fn daemon_is_alive(daemon: &str, pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|comm| comm_names(&comm, daemon))
}

/// Whether `comm` — a `/proc/<pid>/comm` as read — names the binary `binary`.
///
/// The kernel clips the name to [`COMM_MAX`] bytes, so a daemon binary with a
/// longer name arrives cut short and is compared as cut.
fn comm_names(comm: &str, binary: &str) -> bool {
    let clipped = &binary.as_bytes()[..binary.len().min(COMM_MAX)];
    comm.trim_end().as_bytes() == clipped
}

/// A running backend, as a `systemd --user` transient unit.
///
/// The Linux half of the two-platform supervisor handle; see
/// `sandbox_exec::Sandboxed` for the macOS half and for why the two are
/// shaped differently. systemd owns the process, so all this holds is the
/// unit's name — everything is done by asking systemd about that name.
pub(super) struct Unit {
    name: String,
    /// Set once the unit has been stopped, so the synchronous `Drop` after an
    /// awaited [`Self::stop`] does not spend a `systemctl` round-trip
    /// stopping something already gone — and warn, since a second stop fails
    /// with [`EXIT_UNIT_NOT_LOADED`].
    stopped: bool,
}

/// `systemctl`'s exit code for an operation on a unit it does not have loaded.
///
/// For a stop, that is the goal state rather than a failure: the unit is gone,
/// whether this call removed it or it was already collected.
const EXIT_UNIT_NOT_LOADED: i32 = 5;

/// Interpret the result of `systemctl --user stop <unit>` for logging.
fn report_stop(unit: &str, status: std::process::ExitStatus) {
    if status.success() {
        info!("stopped backend unit {unit}");
    } else if status.code() == Some(EXIT_UNIT_NOT_LOADED) {
        info!("backend unit {unit} was already gone");
    } else {
        warn!("systemctl --user stop {unit} exited with {status}; subprocess may still be running");
    }
}

impl Unit {
    /// The unit name, for log lines and error messages.
    pub(super) fn label(&self) -> &str {
        &self.name
    }

    /// Recent backend output, for a diagnostic.
    pub(super) fn logs(&self) -> String {
        std::process::Command::new("journalctl")
            .args(["--user", "-u", &self.name, "--no-pager", "-n", "30"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }

    /// Stop the unit, awaiting its exit.
    pub(super) async fn stop(&mut self) {
        // Set even when the stop fails: the attempt was made, and `Drop`
        // repeating it moments later would not succeed where this did not.
        // The startup sweep is what recovers a unit that truly survived.
        if std::mem::replace(&mut self.stopped, true) {
            return;
        }
        match tokio::process::Command::new("systemctl")
            .args(["--user", "stop", &self.name])
            .status()
            .await
        {
            Ok(status) => report_stop(&self.name, status),
            Err(e) => warn!("failed to invoke systemctl to stop {}: {e}", self.name),
        }
    }

    /// Stop the unit from a synchronous context (`Drop`).
    ///
    /// Blocks the calling thread while `systemctl --user stop` waits for the
    /// unit to exit (usually under a second). Surfaces the result so a
    /// failure doesn't silently leave the subprocess running — a bare
    /// `let _ = …` here made the "backend not stopping" failure mode
    /// invisible.
    pub(super) fn stop_blocking(&mut self) {
        if std::mem::replace(&mut self.stopped, true) {
            return;
        }
        match std::process::Command::new("systemctl")
            .args(["--user", "stop", &self.name])
            .status()
        {
            Ok(status) => report_stop(&self.name, status),
            Err(e) => warn!("failed to invoke systemctl to stop {}: {e}", self.name),
        }
    }
}

impl Drop for Unit {
    fn drop(&mut self) {
        self.stop_blocking();
    }
}

/// Stop a unit of this name that this daemon left behind, and wait for
/// systemd to forget it.
///
/// `systemd-run --unit=<name>` refuses outright when a unit of that name is
/// already loaded — "Unit ... was already loaded or has a fragment file" — and
/// the name is derived from the daemon's pid and the instance, so every
/// attempt at one model within one daemon asks for the same name. No live
/// handle holds it — the spawn claimed the instance first — so a unit still
/// under the name is one this daemon lost track of: a load abandoned after
/// `systemd-run` had started the unit, or a stop that did not take. Left
/// there, it keeps the model unloadable until the daemon itself restarts.
///
/// Failures are logged rather than propagated. Every one of them means the
/// unit is not running, which is what the caller wanted.
async fn stop_stale_unit(unit: &str) {
    let stopped = tokio::process::Command::new("systemctl")
        .args(["--user", "stop", unit])
        .status()
        .await;
    match stopped {
        Ok(s) if s.success() => info!("stopped a stale {unit} before relaunching it"),
        Ok(_) => return, // Nothing of that name was running.
        Err(e) => {
            warn!("could not stop a stale {unit}: {e}");
            return;
        }
    }
    // A failed unit lingers under its name until it is reset, and `stop`
    // returns before systemd has finished tearing the unit down. `--collect`
    // often has the unit gone already, and systemctl says so on stderr; that
    // is the expected case here, not something to print at a user.
    let _ = tokio::process::Command::new("systemctl")
        .args(["--user", "reset-failed", unit])
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let load_state = tokio::process::Command::new("systemctl")
            .args(["--user", "show", "-p", "LoadState", "--value", unit])
            .output()
            .await;
        match load_state {
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "not-found" => return,
            Ok(_) => {}
            Err(e) => {
                warn!("could not read the state of {unit}: {e}");
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    warn!("{unit} is still loaded after being stopped; the spawn may be refused");
}

/// Spawn the backend binary in a hardened `systemd-run --user` transient unit.
///
/// The unit is named `<slug>-backend-<instance>-<daemon pid>`: the prefix is
/// what [`cleanup_orphan_units`] sweeps by, and the pid is what keeps two
/// daemons' units distinct. `s.devices` is the model's declared
/// `supported_devices`; it decides whether this unit is granted the GPU
/// device nodes. See [`needs_gpu_access`].
pub(super) async fn spawn_sandboxed(s: &Sandbox<'_>) -> Result<Unit> {
    let unit = format!(
        "{}{}-{}",
        unit_prefix(s.product),
        s.instance,
        std::process::id()
    );

    // Both of these are about relaunching an instance this daemon started
    // once and lost track of: the unit name would collide, and the socket is
    // the leftover backend's until its unit is gone. Stopped first, so a
    // refused spawn cannot take a serving backend's socket with it.
    stop_stale_unit(&unit).await;
    let _ = std::fs::remove_file(s.socket);

    let mut cmd = tokio::process::Command::new("systemd-run");
    cmd.arg("--user")
        .arg(format!("--unit={unit}"))
        .arg("--quiet")
        // Garbage-collect the transient unit when it exits/fails.
        .arg("--collect");
    for param in hardening_params(
        s.backend_dir,
        s.socket_dir,
        s.cache_dir,
        needs_gpu_access(s.devices),
    ) {
        cmd.arg("-p").arg(param);
    }
    for (key, value) in backend_env(s.product, s.socket, s.backend_dir, s.cache_dir) {
        cmd.arg(format!("--setenv={key}={value}"));
    }
    cmd.arg(s.binary);

    let output = cmd.output().await.context("failed to run systemd-run")?;
    if !output.status.success() {
        bail!(
            "systemd-run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    warn!("spawned sandboxed backend unit {unit}");
    Ok(Unit {
        name: unit,
        stopped: false,
    })
}

/// Whether a model that declares `devices` is granted the GPU device nodes.
///
/// Exposing the GPU device nodes (NVIDIA's `/dev/nvidia*`, AMD's `/dev/kfd`,
/// and the DRM render nodes both share) hands the backend privileged kernel
/// attack surface, so they are withheld from the models that provably cannot
/// use them: those whose `supported_devices` name no GPU.
///
/// The *runtime* device preference deliberately does not decide this. The
/// sandbox is fixed when the unit spawns, which happens before `load` — at
/// that point no preference for this model exists yet (the settings UI offers
/// the device picker only once a model is loaded), and the persisted default
/// would hide the GPU from a CUDA-only model. A model's declared capability is
/// known from `backend.toml` at spawn time and does not move afterwards, so a
/// GPU-capable model keeps the nodes whether or not the user currently prefers
/// the CPU — switching device must not depend on how the unit was spawned.
fn needs_gpu_access(devices: &[Device]) -> bool {
    devices.iter().any(|d| matches!(d, Device::Gpu))
}

/// Conventional first DRM render node, used when `/dev/dri` cannot be read.
const FALLBACK_RENDER_NODE: &str = "/dev/dri/renderD128";

/// The device nodes a GPU-capable backend is granted.
///
/// NVIDIA's nodes are fixed names. AMD reaches the driver through `/dev/kfd`
/// (`ROCm`'s compute interface) plus a DRM render node, and Vulkan through the
/// render node alone. The render minor is not derivable from the probe —
/// `gpu_probe::GpuInfo` does not expose KFD's `drm_render_minor` — so every
/// present node is granted rather than guessing one.
fn gpu_device_nodes() -> Vec<String> {
    gpu_device_nodes_in(Path::new("/dev/dri"))
}

/// [`gpu_device_nodes`], parameterized on the DRM directory so the
/// enumeration/sort/fallback behavior is testable against a fixture
/// directory instead of the real (and test-host-dependent) `/dev/dri`.
fn gpu_device_nodes_in(dri_dir: &Path) -> Vec<String> {
    let mut nodes: Vec<String> = [
        "/dev/nvidia0",
        "/dev/nvidiactl",
        "/dev/nvidia-uvm",
        "/dev/nvidia-uvm-tools",
        "/dev/kfd",
    ]
    .iter()
    .map(|n| format!("DeviceAllow={n} rw"))
    .collect();

    let mut render: Vec<String> = std::fs::read_dir(dri_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("renderD"))
        })
        .map(|p| format!("DeviceAllow={} rw", p.display()))
        .collect();
    render.sort();
    if render.is_empty() {
        render.push(format!("DeviceAllow={FALLBACK_RENDER_NODE} rw"));
    }
    nodes.extend(render);
    nodes
}

/// The systemd sandbox directives applied to every spawned backend. Shared by
/// the spawner and the sandbox-enforcement tests so they stay in lock-step.
///
/// - `PrivateNetwork`: no network — the daemon already provisioned files.
/// - `ProtectSystem=strict` + `ProtectHome=read-only`: the filesystem is
///   read-only (the binary + model under `$HOME` stay visible read-only); only
///   the socket dir and the backend's cache dir are writable.
/// - `ReadWritePaths=<cache dir>`: the one place a backend may keep something
///   across runs. `PrivateTmp` is writable too but is discarded with the unit,
///   which is no home for a kernel cache that costs twenty seconds to rebuild.
/// - `PrivateTmp`, `NoNewPrivileges`, `SystemCallFilter=@system-service`.
/// - `PrivateDevices` (models declaring no GPU): a private `/dev` holding just
///   the pseudo-devices, so the GPU nodes are not there to open.
/// - `DevicePolicy=closed` + `DeviceAllow`: the intended device allowlist —
///   the NVIDIA nodes, `/dev/kfd` for `ROCm`, and every enumerated DRM render
///   node (see [`gpu_device_nodes`]) — granted only when the spawned model
///   declares GPU support.
///
/// The device *cgroup* controller (`DevicePolicy`/`DeviceAllow`) is only
/// enforced for system units — a per-user manager records the properties and
/// runs the unit without them, because installing the BPF device program is
/// privileged. They are declared anyway so the policy is right if these units
/// ever move to the system manager, but the CPU-only restriction cannot lean
/// on them. `PrivateDevices` carries it instead: it is a mount namespace, so
/// it applies to user units exactly as `PrivateTmp` does.
fn hardening_params(
    backend_dir: &Path,
    socket_dir: &Path,
    cache_dir: &Path,
    gpu_access: bool,
) -> Vec<String> {
    let mut params = vec![
        "PrivateNetwork=yes".to_string(),
        "ProtectSystem=strict".to_string(),
        "ProtectHome=read-only".to_string(),
        format!("ReadOnlyPaths={}", backend_dir.display()),
        format!("ReadWritePaths={}", socket_dir.display()),
        format!("ReadWritePaths={}", cache_dir.display()),
        "PrivateTmp=yes".to_string(),
        "NoNewPrivileges=yes".to_string(),
        "DevicePolicy=closed".to_string(),
    ];
    if gpu_access {
        params.extend(gpu_device_nodes());
    } else {
        params.push("PrivateDevices=yes".to_string());
    }
    params.push("SystemCallFilter=@system-service".to_string());
    params
}

#[cfg(test)]
mod orphan_tests {
    use super::{comm_names, is_orphaned_unit};

    const DEAD: fn(u32) -> bool = |_| false;
    const LIVE: fn(u32) -> bool = |_| true;

    /// The sweep exists for units a dead daemon left holding a model.
    #[test]
    fn a_unit_whose_daemon_is_gone_is_swept() {
        assert!(is_orphaned_unit(
            "super-test-backend-app-super-test-big-model-1-7b-4242.service",
            DEAD
        ));
        // Also without the suffix, which is how `list-units` prints some rows.
        assert!(is_orphaned_unit("super-test-backend-small-4242", DEAD));
    }

    /// The regression this guards: a second daemon starting must not pull the
    /// backend out from under one that is serving. Every failure it caused
    /// looked like something else — a daemon reporting a model loaded with
    /// nothing behind the socket, or two backends fighting for the GPU.
    #[test]
    fn a_unit_belonging_to_a_live_daemon_is_left_alone() {
        assert!(!is_orphaned_unit(
            "super-test-backend-app-super-test-big-model-1-7b-4242.service",
            LIVE
        ));
    }

    /// Our own units are never orphans, however this is called.
    #[test]
    fn this_daemons_own_units_are_never_swept() {
        let mine = format!("super-test-backend-small-{}", std::process::id());
        assert!(!is_orphaned_unit(&mine, DEAD));
    }

    /// A name that carries no PID is left alone rather than guessed at: the
    /// cost of keeping a unit is memory, the cost of sweeping a live one is a
    /// broken daemon.
    #[test]
    fn an_unparseable_name_is_left_alone() {
        assert!(!is_orphaned_unit("super-test-backend-.service", DEAD));
        assert!(!is_orphaned_unit(
            "super-test-backend-small-notapid.service",
            DEAD
        ));
    }

    /// The instance contains dashes of its own, so the PID is the segment
    /// after the last one — not the second.
    #[test]
    fn the_pid_is_read_from_the_end_of_a_dashed_instance() {
        let seen = std::cell::Cell::new(0);
        assert!(is_orphaned_unit(
            "super-test-backend-app-super-test-big-model-1-7b-991.service",
            |pid| {
                seen.set(pid);
                false
            }
        ));
        assert_eq!(
            seen.get(),
            991,
            "the instance's own dashes are not the split"
        );
    }

    /// The kernel keeps 15 bytes of a process name, so a daemon binary named
    /// longer than that is only ever seen cut short — and must still be
    /// recognized, or every live daemon would look dead and its backends
    /// would be swept.
    #[test]
    fn a_daemon_is_recognized_by_the_name_the_kernel_keeps() {
        assert!(comm_names("super-test-daem\n", "super-test-daemon"));
        assert!(comm_names("short-daemon\n", "short-daemon"));
        // A recycled pid now running something else is not the daemon.
        assert!(!comm_names("bash\n", "super-test-daemon"));
        // Nor is another product's daemon.
        assert!(!comm_names("super-other-dae\n", "super-test-daemon"));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Device, FALLBACK_RENDER_NODE, gpu_device_nodes_in, hardening_params, needs_gpu_access,
        stop_stale_unit,
    };
    use std::path::{Path, PathBuf};

    /// A model that declares no GPU device must not be handed the GPU nodes.
    /// The GPU driver is privileged kernel attack surface, so the sandbox
    /// opens it only for the backends that can actually compute on it.
    ///
    /// `PrivateDevices` is what makes this real: the daemon spawns `--user`
    /// units, and a per-user manager does not enforce the device cgroup
    /// controller, so dropping the `DeviceAllow` lines alone would restrict
    /// nothing. `sandbox_is_enforced` proves the denial end-to-end.
    #[test]
    fn a_cpu_only_model_gets_no_gpu_device_nodes() {
        let params = hardening_params(
            Path::new("/backend"),
            Path::new("/sock"),
            Path::new("/cache"),
            false,
        );
        assert!(
            params.iter().any(|p| p == "PrivateDevices=yes"),
            "cpu-only unit has no enforceable device restriction: {params:?}"
        );
        assert!(
            !params.iter().any(|p| p.starts_with("DeviceAllow=")),
            "cpu-only unit was granted device nodes: {params:?}"
        );
    }

    /// The GPU path gets every node any supported runtime needs, and must NOT
    /// get the private `/dev` — that would hide the GPU from the one backend
    /// that needs it, failing at model-load time as an opaque driver error
    /// rather than as a permission problem.
    #[test]
    fn a_gpu_backend_gets_the_nodes_every_runtime_needs() {
        let params = hardening_params(
            Path::new("/backend"),
            Path::new("/sock"),
            Path::new("/cache"),
            true,
        );
        assert!(!params.iter().any(|p| p == "PrivateDevices=yes"));
        for node in [
            "DeviceAllow=/dev/nvidia0 rw",
            "DeviceAllow=/dev/nvidiactl rw",
            "DeviceAllow=/dev/nvidia-uvm rw",
            "DeviceAllow=/dev/nvidia-uvm-tools rw",
            // ROCm and Vulkan reach the AMD driver through KFD; without this a
            // ROCm backend is sandboxed out of its own GPU.
            "DeviceAllow=/dev/kfd rw",
        ] {
            assert!(params.iter().any(|p| p == node), "missing {node}");
        }
        assert!(
            params
                .iter()
                .any(|p| p.starts_with("DeviceAllow=/dev/dri/renderD")),
            "no DRM render node granted: {params:?}"
        );
    }

    #[test]
    fn gpu_access_follows_the_gpu_device() {
        assert!(!needs_gpu_access(&[Device::Cpu]));
        assert!(!needs_gpu_access(&[Device::None]));
        assert!(!needs_gpu_access(&[]));
        assert!(needs_gpu_access(&[Device::Gpu]));
        assert!(needs_gpu_access(&[Device::Cpu, Device::Gpu]));
    }

    /// The render minor is not knowable from the probe — `GpuInfo` does not
    /// expose KFD's `drm_render_minor` — so the nodes are enumerated from a
    /// real DRM directory rather than guessed. Driven through
    /// `gpu_device_nodes_in` against a fixture directory: the real
    /// `gpu_device_nodes()` reading the test host's actual `/dev/dri` would
    /// let a hardcoded stub pass this test on any machine, and would make the
    /// fallback/sort/multi-node cases untestable at all.
    #[test]
    fn render_nodes_are_enumerated_and_sorted() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["renderD129", "renderD128", "card0", "by-path"] {
            std::fs::write(dir.path().join(name), b"").expect("writes fixture entry");
        }
        let nodes = gpu_device_nodes_in(dir.path());
        assert!(nodes.iter().any(|n| n.contains("/dev/kfd")));
        let render: Vec<&String> = nodes.iter().filter(|n| n.contains("renderD")).collect();
        assert_eq!(
            render,
            vec![
                &format!("DeviceAllow={} rw", dir.path().join("renderD128").display()),
                &format!("DeviceAllow={} rw", dir.path().join("renderD129").display()),
            ],
            "non-render entries must be filtered out and render nodes sorted: {nodes:?}"
        );
    }

    /// An empty or unreadable DRM directory still yields a well-formed
    /// policy: the conventional first render node, not zero `DeviceAllow`
    /// lines for the GPU a unit was granted access to.
    #[test]
    fn render_nodes_fall_back_when_the_drm_directory_has_no_render_node() {
        let empty = tempfile::tempdir().expect("tempdir");
        let nodes = gpu_device_nodes_in(empty.path());
        assert_eq!(
            nodes.iter().filter(|n| n.contains("renderD")).count(),
            1,
            "empty dir must fall back to exactly one render node: {nodes:?}"
        );
        assert!(
            nodes
                .iter()
                .any(|n| n == &format!("DeviceAllow={FALLBACK_RENDER_NODE} rw"))
        );

        let missing = empty.path().join("does-not-exist");
        let nodes = gpu_device_nodes_in(&missing);
        assert!(
            nodes
                .iter()
                .any(|n| n == &format!("DeviceAllow={FALLBACK_RENDER_NODE} rw")),
            "an unreadable dir must fall back too: {nodes:?}"
        );
    }

    /// The cache directory must be granted as writable, and must not be
    /// confused with the backend directory, which stays read-only. Both are
    /// under `$HOME` on a real install, where `ProtectHome=read-only` covers
    /// them until `ReadWritePaths` carves the cache back out; dropping that
    /// line is silent — the backend keeps working and merely recompiles its
    /// kernels on every load — so it is asserted here rather than left to the
    /// env-gated enforcement test.
    #[test]
    fn the_cache_dir_is_the_second_writable_path() {
        let params = hardening_params(
            Path::new("/data/backends/app.super-test.big"),
            Path::new("/run/user/1000/test/backends"),
            Path::new("/cache/super-test/backends/app-super-test-big"),
            true,
        );
        assert!(
            params.contains(
                &"ReadWritePaths=/cache/super-test/backends/app-super-test-big".to_string()
            ),
            "the cache dir must be writable: {params:?}"
        );
        assert!(
            params.contains(&"ReadOnlyPaths=/data/backends/app.super-test.big".to_string()),
            "the backend dir must stay read-only: {params:?}"
        );
        assert!(
            params.contains(&"ReadWritePaths=/run/user/1000/test/backends".to_string()),
            "the socket dir must stay writable: {params:?}"
        );
    }

    /// A unit name can be reused once the unit holding it has been stopped.
    ///
    /// The name a backend spawns under is fixed by the instance and the
    /// daemon's pid, so relaunching a model asks systemd for a name it may
    /// still be holding — and `systemd-run` refuses rather than replacing it.
    /// This is the whole of that failure and its repair, in the order the
    /// spawn path performs them.
    ///
    /// Requires a systemd user session; gated behind
    /// `SUPER_ENGINE_TEST_SANDBOX=1`.
    #[tokio::test]
    async fn a_unit_name_is_reusable_after_its_unit_is_stopped() {
        if std::env::var("SUPER_ENGINE_TEST_SANDBOX").is_err() {
            return;
        }
        let unit = format!("super-test-backend-relaunch-{}", std::process::id());
        let spawn = || async {
            tokio::process::Command::new("systemd-run")
                .args([
                    "--user",
                    &format!("--unit={unit}"),
                    "--quiet",
                    "--collect",
                    "sleep",
                    "300",
                ])
                .output()
                .await
                .expect("systemd-run must run")
        };

        assert!(spawn().await.status.success(), "the first spawn must work");
        let refused = spawn().await;
        assert!(
            !refused.status.success()
                && String::from_utf8_lossy(&refused.stderr).contains("already loaded"),
            "a second spawn under the same name must be refused: {refused:?}"
        );

        stop_stale_unit(&unit).await;
        let after = spawn().await;
        let ok = after.status.success();
        // Stop it before asserting, so a failure here does not leave a unit
        // running for the next test to trip over.
        stop_stale_unit(&unit).await;
        assert!(
            ok,
            "the name must be free once the unit is stopped: {after:?}"
        );
    }

    /// Verify the systemd sandbox actually *enforces* its restrictions: a probe
    /// run under the same hardening as a real backend must be denied network,
    /// writes to `$HOME` and the system, host `/tmp` visibility, and
    /// non-allowed devices — while keeping `NoNewPrivileges` set and the socket
    /// and cache dirs writable. The cache dir sits *under* `$HOME`, so it is
    /// also the proof that its `ReadWritePaths` beats `ProtectHome=read-only`
    /// rather than being shadowed by it.
    ///
    /// Requires a systemd user session; gated behind
    /// `SUPER_ENGINE_TEST_SANDBOX=1`.
    #[tokio::test]
    async fn sandbox_is_enforced() {
        if std::env::var("SUPER_ENGINE_TEST_SANDBOX").is_err() {
            return;
        }
        let home = std::env::var("HOME").expect("HOME");
        let base = PathBuf::from(&home).join(".cache/super-engine-sandbox-test");
        let backend_dir = base.join("backend");
        let socket_dir = base.join("sock");
        let cache_dir = base.join("cache");
        std::fs::create_dir_all(&backend_dir).unwrap();
        std::fs::create_dir_all(&socket_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(backend_dir.join("backend.toml"), "probe = true\n").unwrap();

        // A host /tmp marker the private-tmp sandbox must NOT see.
        let marker = format!("/tmp/sbx-marker-{}", std::process::id());
        std::fs::write(&marker, "host").unwrap();

        let probe = format!(
            r#"
nonlo=$(awk -F: 'NR>2 {{ gsub(/ /,"",$1); if ($1 != "lo") print $1 }}' /proc/net/dev)
[ -z "$nonlo" ] && echo NET_ISOLATED || echo "NET_LEAK:$nonlo"
touch "$HOME/.sbx_$$" 2>/dev/null && {{ echo HOME_WRITABLE; rm -f "$HOME/.sbx_$$"; }} || echo HOME_RO
touch /etc/.sbx_$$ 2>/dev/null && echo ETC_WRITABLE || echo ETC_RO
grep -q "NoNewPrivs:[[:space:]]*1" /proc/self/status && echo NNP_SET || echo NNP_UNSET
[ -e "{marker}" ] && echo TMP_LEAK || echo TMP_PRIVATE
touch "{sock}/.sbx_$$" 2>/dev/null && {{ echo SOCK_RW; rm -f "{sock}/.sbx_$$"; }} || echo SOCK_RO
touch "{cache}/.sbx_$$" 2>/dev/null && {{ echo CACHE_RW; rm -f "{cache}/.sbx_$$"; }} || echo CACHE_RO
touch "{backend}/.sbx_$$" 2>/dev/null && echo BACKEND_WRITABLE || echo BACKEND_RO
[ -r "{backend}/backend.toml" ] && echo BACKEND_READABLE || echo BACKEND_HIDDEN
[ -e /dev/nvidia0 ] && echo GPU_NODE_PRESENT || echo GPU_NODE_ABSENT
"#,
            marker = marker,
            sock = socket_dir.display(),
            cache = cache_dir.display(),
            backend = backend_dir.display(),
        );

        let mut cmd = tokio::process::Command::new("systemd-run");
        cmd.arg("--user")
            .arg("--pipe")
            .arg("--quiet")
            .arg("--collect");
        for p in hardening_params(&backend_dir, &socket_dir, &cache_dir, true) {
            cmd.arg("-p").arg(p);
        }
        cmd.arg("--").arg("sh").arg("-c").arg(&probe);

        let out = cmd.output().await.expect("run systemd-run");
        let _ = std::fs::remove_file(&marker);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        println!("--- probe stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

        for expected in [
            "NET_ISOLATED",
            "HOME_RO",
            "ETC_RO",
            "NNP_SET",
            "TMP_PRIVATE",
            "SOCK_RW",
            "CACHE_RW",
            "BACKEND_RO",
            "BACKEND_READABLE",
        ] {
            assert!(
                stdout.contains(expected),
                "sandbox property not enforced: {expected}\n{stdout}\n{stderr}"
            );
        }
        for violation in [
            "HOME_WRITABLE",
            "ETC_WRITABLE",
            "TMP_LEAK",
            "NET_LEAK",
            "CACHE_RO",
            "BACKEND_WRITABLE",
        ] {
            assert!(
                !stdout.contains(violation),
                "sandbox violation detected: {violation}\n{stdout}"
            );
        }

        // The GPU half of the check needs a host that actually has the node —
        // otherwise "absent under the CPU params" is true for the wrong reason
        // and proves nothing.
        if !Path::new("/dev/nvidia0").exists() {
            return;
        }
        assert!(
            stdout.contains("GPU_NODE_PRESENT"),
            "a GPU backend cannot see the GPU it was granted\n{stdout}\n{stderr}"
        );

        // Same probe under the params a model declaring no GPU would get.
        // Asserting on the parameter list alone would only prove we omit a
        // string; this proves systemd enforces the omission — and it is the
        // reason that case carries `PrivateDevices` rather than just dropping
        // the `DeviceAllow` lines, which a per-user manager ignores.
        let mut cmd = tokio::process::Command::new("systemd-run");
        cmd.arg("--user")
            .arg("--pipe")
            .arg("--quiet")
            .arg("--collect");
        for p in hardening_params(&backend_dir, &socket_dir, &cache_dir, false) {
            cmd.arg("-p").arg(p);
        }
        cmd.arg("--").arg("sh").arg("-c").arg(&probe);

        let out = cmd.output().await.expect("run systemd-run");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("GPU_NODE_ABSENT"),
            "a model declaring no GPU was left the GPU node\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
