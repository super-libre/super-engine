// SPDX-License-Identifier: GPL-3.0-only
//! Which framework a model runs on: the preference a client sets, what a host,
//! an installed backend and a model can each offer, and what the host's GPUs
//! are.
//!
//! A preference is a framework: `cpu`, `cuda`, `rocm`, `metal` or `vulkan`.
//! What the daemon records as *actual* is the framework the model really runs
//! on, which is the preference unless the load fell back to the CPU. A
//! manifest still declares what a model supports on the `cpu`/`gpu` axis,
//! which [`capability`] maps a framework onto.

use super_engine_protocol::models::gpu::{
    CudaHostInfo, GpuHostInfo, GpuInfo, RocmHostInfo, VulkanHostInfo,
};
use super_engine_spec::manifest::{Accel, Device, SubprocessAsset};

use crate::backends::ModelDefinition;
use crate::registry::compat;
use crate::registry::host::Host;

/// Every framework, best first: the order every framework list is in.
const FRAMEWORKS: [&str; 5] = ["cuda", "rocm", "metal", "vulkan", "cpu"];

/// Normalize a requested preference, or `None` when it is not a framework.
///
/// `gpu` is not one: a GPU is reached through a framework, and which one is
/// the choice. `none` is a model property, not a preference a client may set.
#[must_use]
pub fn parse_device_preference(device: &str) -> Option<String> {
    device.parse::<Accel>().ok().map(|accel| accel.to_string())
}

/// Whether `framework` runs on the GPU or the CPU: the axis a manifest
/// declares what a model supports on. `remote` and anything unrecognized stay
/// themselves, since neither is a local framework.
#[must_use]
pub fn capability(framework: &str) -> &str {
    match framework {
        "cuda" | "rocm" | "metal" | "vulkan" => "gpu",
        other => other,
    }
}

/// Whether a requested switch is already in effect, and so has nothing to do.
///
/// The model must be running on the framework asked for, not only have it
/// stored: one that fell back to the CPU is retried by asking again.
#[must_use]
pub fn switch_is_satisfied(current_preferred: &str, current_actual: &str, requested: &str) -> bool {
    current_preferred == requested && current_actual == requested
}

/// The message a completed switch reports. Only a GPU framework that landed
/// on the CPU is a fallback.
#[must_use]
pub fn device_switch_message(requested: &str, actual_device: &str) -> String {
    if requested != "cpu" && actual_device == "cpu" {
        format!("Switch to {requested} requested, but the model fell back to the CPU")
    } else {
        format!("Successfully switched to {actual_device}")
    }
}

/// The frameworks this host has, best first, the CPU last.
#[must_use]
pub fn host_available_devices(host: &Host) -> Vec<String> {
    host.frameworks().iter().map(ToString::to_string).collect()
}

/// The frameworks an installed backend could run on here: every framework a
/// build named in its `backend.toml` would run on this host, installed or
/// not, since another build can be installed. A build runs on the frameworks
/// its `accel` lists and no others: a CUDA build that also runs on the CPU
/// says so with `accel = ["cuda", "cpu"]`.
///
/// A backend whose manifest names no builds has only what is on disk: the
/// frameworks its install record names that the host has. A WASM component
/// runs on the CPU. With no record at all (a directory imported by hand)
/// nothing says what the build carries, so the backend is taken at its word
/// and offered every framework the host has; a load it cannot do falls back.
#[must_use]
pub fn backend_frameworks(
    host: &Host,
    assets: &[SubprocessAsset],
    installed_accel: &[String],
) -> Vec<String> {
    let runnable = compat::runnable_manifest_accels(host, assets);
    if !runnable.is_empty() {
        return runnable.iter().map(ToString::to_string).collect();
    }
    if installed_accel.iter().any(|a| a == "wasm") {
        return vec!["cpu".to_string()];
    }
    let frameworks = host_available_devices(host);
    if installed_accel.is_empty() {
        return frameworks;
    }
    frameworks
        .into_iter()
        .filter(|f| installed_accel.contains(f))
        .collect()
}

/// The frameworks a model can be offered here: those of its backend
/// ([`backend_frameworks`]) on the axis the model declares. A model declaring
/// only `cpu` is not offered a GPU framework, nor a GPU-only model the CPU.
/// Online models (`none`) offer nothing: there is no local compute.
#[must_use]
pub fn model_available_devices(declared: &[Device], frameworks: &[String]) -> Vec<String> {
    if declared.contains(&Device::None) {
        return Vec::new();
    }
    frameworks
        .iter()
        .filter(|f| declared.iter().any(|d| d.to_string() == capability(f)))
        .cloned()
        .collect()
}

/// The frameworks a backend's models can run on here: the union of what each
/// is offered, best first.
#[must_use]
pub fn backend_available_devices(per_model: impl IntoIterator<Item = Vec<String>>) -> Vec<String> {
    let offered: Vec<String> = per_model.into_iter().flatten().collect();
    FRAMEWORKS
        .iter()
        .filter(|f| offered.iter().any(|o| o == *f))
        .map(ToString::to_string)
        .collect()
}

/// Whether the build on disk runs on `framework`, so a switch to it can load
/// at once rather than first installing another build: whether its record,
/// copied from the build's `accel`, names it. Whisper's CUDA build declares
/// `["cuda", "cpu"]` and moves to the CPU at once; Qwen's declares `cuda`
/// alone and has no CPU path.
///
/// An install with no record (a local import, or a WASM component, whose
/// record names a transport) is taken at its word: there is no other build to
/// install, and the backend says at load what it can do.
#[must_use]
pub fn build_installed(framework: &str, installed_accel: &[String]) -> bool {
    let named: Vec<&String> = installed_accel.iter().filter(|a| *a != "wasm").collect();
    named.is_empty() || named.iter().any(|a| a.as_str() == framework)
}

/// The framework a model runs on when none was chosen: the best one offered
/// that the build on disk runs, or the best one offered.
#[must_use]
pub fn default_framework(offered: &[String], installed_accel: &[String]) -> Option<String> {
    offered
        .iter()
        .find(|f| build_installed(f, installed_accel))
        .or_else(|| offered.first())
        .cloned()
}

/// The framework a model loads on: its own choice, `chosen`, when it is
/// offered here and its build is installed, else [`default_framework`]: the
/// best framework offered that the build on disk runs. There is no global
/// default between the two, so a model nobody chose a framework for runs on
/// the best one it can, not on the CPU.
///
/// A client staging a load from this never asks for a build that is not
/// installed. A choice whose build was replaced since stays stored, and is
/// used again once that build is back. `None` when nothing is offered: an
/// online model, or one no build of its backend runs here.
#[must_use]
pub fn effective_framework(
    chosen: Option<&str>,
    offered: &[String],
    installed_accel: &[String],
) -> Option<String> {
    if let Some(chosen) = chosen
        && offered.iter().any(|f| f == chosen)
        && build_installed(chosen, installed_accel)
    {
        return Some(chosen.to_string());
    }
    default_framework(offered, installed_accel)
}

/// Why a model cannot be set to `framework` at all, or `None` when it can.
///
/// Only the manifest is consulted: an online model has no local device, and a
/// model declaring only `cpu` cannot be sent to a GPU framework. Whether this
/// host has it, or the build for it is installed, is the device list's
/// question and the switch's, not a rejection. A daemon answers the message
/// as its `invalid_device` error.
#[must_use]
pub fn device_rejection<M>(definition: &ModelDefinition<M>, framework: &str) -> Option<String> {
    let name = &definition.name;
    if definition.is_online() {
        return Some(format!(
            "Model {name} runs on a remote service and has no local device to set."
        ));
    }
    let declared: Vec<String> = definition
        .supported_devices
        .iter()
        .map(ToString::to_string)
        .collect();
    if declared.iter().any(|d| d == capability(framework)) {
        return None;
    }
    Some(format!(
        "Model {name} does not run on {framework}; it supports {}.",
        declared.join(", ")
    ))
}

/// The host's GPUs, and the GPU runtimes installed on it: what
/// `GET /gpu_info` answers. Probes the hardware, so it blocks; call it from
/// `spawn_blocking`.
#[must_use]
pub fn gpu_info() -> (Vec<GpuInfo>, GpuHostInfo) {
    let gpus = gpu_probe::detect().into_iter().map(gpu_to_wire).collect();
    (gpus, gpu_host_to_wire())
}

/// Render a probed architecture target for the wire.
///
/// `ArchTarget`'s `Display` already emits each vendor's own spelling —
/// `sm_86` for CUDA, `gfx1030` for `--offload-arch` — so this exists only to
/// carry `None` through as `null` and to give that behavior a test, since
/// `gpu_probe::GpuInfo` is `#[non_exhaustive]` and cannot be built here.
fn arch_label(target: Option<gpu_probe::ArchTarget>) -> Option<String> {
    target.map(|t| t.to_string())
}

/// Map a [`gpu_probe::GpuInfo`] to the wire payload, normalizing the vendor to
/// its `snake_case` tag (`nvidia` / `amd` / `intel` / `apple` / `unknown`).
fn gpu_to_wire(gpu: gpu_probe::GpuInfo) -> GpuInfo {
    let vendor = match gpu.vendor {
        gpu_probe::Vendor::Nvidia => "nvidia",
        gpu_probe::Vendor::Amd => "amd",
        gpu_probe::Vendor::Intel => "intel",
        gpu_probe::Vendor::Apple => "apple",
        _ => "unknown",
    }
    .to_string();
    let arch_target = arch_label(gpu.arch_target);
    GpuInfo {
        name: gpu.name,
        vendor,
        total_bytes: gpu.total_bytes,
        free_bytes: gpu.free_bytes,
        used_bytes: gpu.used_bytes,
        arch_target,
    }
}

/// Build the `/gpu_info` host block from `gpu-probe`'s raw toolchain probes.
///
/// Deliberately the *unfiltered* facts, unlike [`host_available_devices`] and
/// the `Host` it reads: that path gates `vulkan` on a GPU actually being
/// present, because a false positive there would make a lavapipe-only host
/// download a GPU asset it should never run. `/gpu_info` is a read-only
/// diagnostics endpoint that mutates nothing and drives no selection, so the
/// safety concern that motivates that gate does not apply here — this reports
/// whichever loader/toolchain is installed, full stop, the same way
/// `host.rocm` already reports a `ROCm` userspace install with no claim about
/// whether a GPU is behind it. A caller wanting "is there a real GPU here"
/// already has that from `gpu_info[].vendor`.
///
fn gpu_host_to_wire() -> GpuHostInfo {
    GpuHostInfo {
        cuda: gpu_probe::cuda_host().map(|h| CudaHostInfo {
            driver_version: h.driver_version.to_string(),
        }),
        rocm: gpu_probe::rocm_host().map(|h| RocmHostInfo {
            version: h.version.to_string(),
        }),
        vulkan: gpu_probe::vulkan_host().map(|h| VulkanHostInfo {
            api_version: h.api_version.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::host::{CudaHost, MetalHost, VulkanHost};

    fn bare_host() -> Host {
        Host {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            cuda: None,
            rocm: None,
            vulkan: None,
            metal: None,
        }
    }

    fn cuda() -> Option<CudaHost> {
        Some(CudaHost {
            compute_capability: 86,
            runtime_major: 12,
            cudnn_present: false,
        })
    }

    fn vulkan() -> Option<VulkanHost> {
        Some(VulkanHost {
            api_version: gpu_probe::VulkanVersion::new(1, 3, 0),
        })
    }

    /// An NVIDIA machine with a Vulkan loader, as most are.
    fn nvidia_host() -> Host {
        Host {
            cuda: cuda(),
            vulkan: vulkan(),
            ..bare_host()
        }
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    fn build(accel: &[Accel], cuda_major: Option<u32>) -> SubprocessAsset {
        SubprocessAsset {
            file: Some("build.tar.gz".into()),
            parts: Vec::new(),
            target: "x86_64-unknown-linux-gnu".into(),
            accel: accel.to_vec(),
            cuda_major,
            cuda_sm: None,
            cudnn: false,
            gfx: Vec::new(),
            vulkan_api: None,
        }
    }

    /// A backend publishing a CUDA, a Vulkan and a CPU build, as Qwen does.
    fn three_builds() -> Vec<SubprocessAsset> {
        vec![
            build(&[Accel::Cuda], Some(12)),
            build(&[Accel::Vulkan], None),
            build(&[Accel::Cpu], None),
        ]
    }

    #[test]
    fn a_host_offers_its_frameworks_best_first() {
        assert_eq!(host_available_devices(&bare_host()), strings(&["cpu"]));
        assert_eq!(
            host_available_devices(&nvidia_host()),
            strings(&["cuda", "vulkan", "cpu"])
        );
        // Metal is the framework on every Mac; leaving it out would offer a
        // Mac the CPU alone.
        let mac = Host {
            metal: Some(MetalHost),
            ..bare_host()
        };
        assert_eq!(host_available_devices(&mac), strings(&["metal", "cpu"]));
    }

    #[test]
    fn a_preference_is_a_framework() {
        for framework in ["cpu", "cuda", "rocm", "metal", "vulkan"] {
            assert_eq!(
                parse_device_preference(framework).as_deref(),
                Some(framework)
            );
        }
        assert_eq!(
            parse_device_preference("gpu"),
            None,
            "a GPU is reached through a framework"
        );
        assert_eq!(parse_device_preference("none"), None, "not a preference");
        assert_eq!(parse_device_preference("nonsense"), None);
    }

    #[test]
    fn a_framework_runs_on_the_gpu_or_the_cpu() {
        for framework in ["cuda", "rocm", "metal", "vulkan"] {
            assert_eq!(capability(framework), "gpu", "{framework}");
        }
        assert_eq!(capability("cpu"), "cpu");
        assert_eq!(capability("remote"), "remote");
    }

    #[test]
    fn an_architecture_target_renders_in_the_vendors_own_spelling() {
        assert_eq!(
            arch_label(Some(gpu_probe::ArchTarget::Sm(
                gpu_probe::ComputeCapability::new(8, 6)
            ))),
            Some("sm_86".to_string())
        );
        assert_eq!(
            arch_label(Some(gpu_probe::ArchTarget::Gfx(gpu_probe::GfxTarget::new(
                10, 3, 0
            )))),
            Some("gfx1030".to_string())
        );
    }

    /// A GPU whose driver reports no target is `null`, never a placeholder
    /// string a client would have to know to ignore.
    #[test]
    fn an_unreported_architecture_is_null() {
        assert_eq!(arch_label(None), None);
    }

    /// A switch is done when the model runs on what was asked: one stored but
    /// fallen back to the CPU is retried, and another framework is a switch.
    #[test]
    fn a_switch_is_satisfied_only_by_running_on_the_framework_asked_for() {
        assert!(switch_is_satisfied("cuda", "cuda", "cuda"));
        assert!(switch_is_satisfied("cpu", "cpu", "cpu"));
        assert!(!switch_is_satisfied("cuda", "cpu", "cuda"), "fell back");
        assert!(!switch_is_satisfied("cuda", "cuda", "vulkan"));
        assert!(!switch_is_satisfied("vulkan", "vulkan", "cpu"));
    }

    #[test]
    fn only_a_gpu_framework_that_landed_on_the_cpu_is_a_fallback() {
        assert_eq!(
            device_switch_message("vulkan", "vulkan"),
            "Successfully switched to vulkan"
        );
        assert_eq!(
            device_switch_message("cpu", "cpu"),
            "Successfully switched to cpu"
        );
        assert_eq!(
            device_switch_message("cuda", "cpu"),
            "Switch to cuda requested, but the model fell back to the CPU"
        );
    }

    /// Every framework a published build would run on here is offered,
    /// whichever one is installed: another build can be installed.
    #[test]
    fn a_backend_offers_every_framework_its_builds_run_on_here() {
        assert_eq!(
            backend_frameworks(&nvidia_host(), &three_builds(), &strings(&["vulkan"])),
            strings(&["cuda", "vulkan", "cpu"])
        );
        let no_loader = Host {
            cuda: cuda(),
            ..bare_host()
        };
        assert_eq!(
            backend_frameworks(&no_loader, &three_builds(), &strings(&["cuda"])),
            strings(&["cuda", "cpu"]),
            "no Vulkan loader, no Vulkan"
        );
        assert_eq!(
            backend_frameworks(&bare_host(), &three_builds(), &[]),
            strings(&["cpu"])
        );
    }

    /// A CUDA build needing a newer runtime than the driver has does not run
    /// here, so CUDA is not offered for it.
    #[test]
    fn a_build_the_host_cannot_run_offers_nothing() {
        let builds = vec![
            build(&[Accel::Cuda], Some(13)),
            build(&[Accel::Vulkan], None),
        ];
        assert_eq!(
            backend_frameworks(&nvidia_host(), &builds, &[]),
            strings(&["vulkan"])
        );
    }

    /// With no builds named, the build on disk is all there is.
    #[test]
    fn without_builds_the_install_record_answers() {
        assert_eq!(
            backend_frameworks(&nvidia_host(), &[], &strings(&["vulkan", "cpu"])),
            strings(&["vulkan", "cpu"])
        );
        assert_eq!(
            backend_frameworks(&nvidia_host(), &[], &strings(&["wasm"])),
            strings(&["cpu"]),
            "a WASM component runs on the CPU"
        );
        assert_eq!(
            backend_frameworks(&nvidia_host(), &[], &[]),
            strings(&["cuda", "vulkan", "cpu"]),
            "no record: taken at its word"
        );
    }

    #[test]
    fn a_model_is_offered_the_frameworks_on_its_axis() {
        let frameworks = strings(&["cuda", "vulkan", "cpu"]);
        assert_eq!(
            model_available_devices(&[Device::Gpu], &frameworks),
            strings(&["cuda", "vulkan"])
        );
        assert_eq!(
            model_available_devices(&[Device::Cpu], &frameworks),
            strings(&["cpu"])
        );
        assert_eq!(
            model_available_devices(&[Device::Cpu, Device::Gpu], &frameworks),
            frameworks
        );
        assert_eq!(
            model_available_devices(&[Device::None], &frameworks),
            Vec::<String>::new(),
            "an online model runs on nothing local"
        );
    }

    #[test]
    fn a_backends_frameworks_are_the_union_of_its_models_best_first() {
        assert_eq!(
            backend_available_devices([
                strings(&["cpu"]),
                strings(&["vulkan", "cuda"]),
                Vec::new()
            ]),
            strings(&["cuda", "vulkan", "cpu"])
        );
        assert_eq!(backend_available_devices([]), Vec::<String>::new());
    }

    #[test]
    fn a_framework_is_installed_when_the_build_on_disk_runs_it() {
        let vulkan_build = strings(&["vulkan"]);
        assert!(build_installed("vulkan", &vulkan_build));
        assert!(!build_installed("cuda", &vulkan_build));
        assert!(
            !build_installed("cpu", &strings(&["cuda"])),
            "a CUDA build that does not declare the CPU has no CPU path"
        );
        assert!(build_installed("cpu", &strings(&["cuda", "cpu"])));
        assert!(build_installed("cuda", &[]), "no record: taken at its word");
        assert!(build_installed("cpu", &strings(&["wasm"])));
    }

    /// Whisper publishes a CPU build and CUDA builds that declare the CPU
    /// too. With a CUDA one installed, the CPU is a move, not a download; with
    /// the CPU one installed, CUDA is a download.
    #[test]
    fn a_build_declaring_the_cpu_moves_to_it_without_a_download() {
        let builds = vec![
            build(&[Accel::Cpu], None),
            build(&[Accel::Cuda, Accel::Cpu], Some(12)),
        ];
        let cuda_build = strings(&["cuda", "cpu"]);
        let offered = backend_frameworks(&nvidia_host(), &builds, &cuda_build);
        assert_eq!(offered, strings(&["cuda", "cpu"]));
        assert!(build_installed("cpu", &cuda_build));
        assert_eq!(
            effective_framework(Some("cpu"), &offered, &cuda_build).as_deref(),
            Some("cpu")
        );

        let cpu_build = strings(&["cpu"]);
        assert!(!build_installed("cuda", &cpu_build));
        assert_eq!(
            effective_framework(Some("cuda"), &offered, &cpu_build).as_deref(),
            Some("cpu")
        );
    }

    /// Qwen's builds each carry one GPU framework and no CPU path, so the CPU
    /// is never offered, whatever its models declare.
    #[test]
    fn builds_declaring_no_cpu_offer_no_cpu() {
        let builds = vec![
            build(&[Accel::Cuda], Some(12)),
            build(&[Accel::Vulkan], None),
        ];
        assert_eq!(
            backend_frameworks(&nvidia_host(), &builds, &strings(&["cuda"])),
            strings(&["cuda", "vulkan"])
        );
    }

    #[test]
    fn with_none_chosen_a_model_runs_on_the_best_installed_framework() {
        let offered = strings(&["cuda", "vulkan", "cpu"]);
        assert_eq!(
            default_framework(&offered, &strings(&["vulkan"])).as_deref(),
            Some("vulkan")
        );
        assert_eq!(
            default_framework(&offered, &strings(&["cuda", "cpu"])).as_deref(),
            Some("cuda")
        );
        assert_eq!(
            default_framework(&strings(&["cpu"]), &strings(&["vulkan"])).as_deref(),
            Some("cpu"),
            "the best offered when none is installed"
        );
        assert_eq!(default_framework(&[], &[]), None);
    }

    #[test]
    fn a_choice_whose_build_is_gone_loads_on_an_installed_one() {
        let offered = strings(&["cuda", "vulkan", "cpu"]);
        let vulkan = strings(&["vulkan"]);
        let effective = |chosen| effective_framework(chosen, &offered, &vulkan);
        assert_eq!(effective(Some("vulkan")).as_deref(), Some("vulkan"));
        assert_eq!(
            effective(Some("cuda")).as_deref(),
            Some("vulkan"),
            "the CUDA build is not installed"
        );
        assert_eq!(
            effective(Some("metal")).as_deref(),
            Some("vulkan"),
            "not offered here"
        );
        assert_eq!(
            effective_framework(Some("cpu"), &offered, &[]).as_deref(),
            Some("cpu")
        );
        assert_eq!(effective_framework(Some("cuda"), &[], &[]), None);
    }

    /// With no choice of its own, a model runs on the best framework the
    /// build on disk runs: Whisper on its CUDA build runs on CUDA, not on the
    /// CPU it also lists.
    #[test]
    fn a_model_with_no_choice_runs_on_the_best_installed_framework() {
        let offered = strings(&["cuda", "cpu"]);
        let whisper = strings(&["cuda", "cpu"]);
        assert_eq!(
            effective_framework(None, &offered, &whisper).as_deref(),
            Some("cuda")
        );
        assert_eq!(
            effective_framework(None, &offered, &strings(&["cpu"])).as_deref(),
            Some("cpu")
        );
        assert_eq!(effective_framework(None, &[], &whisper), None);
    }

    fn definition(devices: Vec<Device>) -> ModelDefinition<()> {
        ModelDefinition {
            name: "m".to_string(),
            source: "github.com/x/y".to_string(),
            is_multilingual: false,
            primary_language: "en".to_string(),
            supported_languages: vec!["en".to_string()],
            estimated_vram_bytes: 0,
            processing_interval: std::time::Duration::from_secs(1),
            supported_devices: devices,
            realtime: false,
            product: (),
            provider: None,
        }
    }

    /// The manifest, and only the manifest, decides what a model may be set
    /// to.
    #[test]
    fn a_model_is_refused_only_what_its_manifest_rules_out() {
        let local = definition(vec![Device::Cpu, Device::Gpu]);
        for framework in ["cpu", "cuda", "vulkan"] {
            assert!(device_rejection(&local, framework).is_none(), "{framework}");
        }

        let cpu_only = definition(vec![Device::Cpu]);
        assert!(device_rejection(&cpu_only, "cpu").is_none());
        let rejection = device_rejection(&cpu_only, "cuda").expect("refused");
        assert!(rejection.contains("supports cpu"), "{rejection}");

        let online = definition(vec![Device::None]);
        for framework in ["cpu", "cuda"] {
            let rejection = device_rejection(&online, framework).expect("refused");
            assert!(rejection.contains("remote service"), "{rejection}");
        }
    }
}
