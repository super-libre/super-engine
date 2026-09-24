// SPDX-License-Identifier: GPL-3.0-only
//! Which device a model runs on: the `cpu`/`gpu` preference a client sets,
//! what a host, an installed build and a model can each offer, and what the
//! host's GPUs are.
//!
//! A preference is `cpu` or `gpu`. What the daemon records as *actual* is the
//! accelerator that preference resolved to (`cuda`, `rocm`, `metal`,
//! `vulkan`), which [`preference_axis`] folds back onto the preference.

use super_engine_protocol::models::gpu::{
    CudaHostInfo, GpuHostInfo, GpuInfo, RocmHostInfo, VulkanHostInfo,
};
use super_engine_spec::manifest::Device;

use crate::backends::ModelDefinition;
use crate::registry::host::Host;

/// Normalize a requested device preference, or `None` when it is not one.
///
/// `cuda` and `metal` are accepted as deprecated spellings of `gpu` so clients
/// shipped before this vocabulary keep working; `none` is a model property, not
/// a preference a client may set, so it is rejected here even though
/// `Device::from_str` parses it.
#[must_use]
pub fn parse_device_preference(device: &str) -> Option<String> {
    match device.parse::<Device>() {
        Ok(Device::Cpu) => Some("cpu".to_string()),
        Ok(Device::Gpu) => Some("gpu".to_string()),
        _ => None,
    }
}

/// Collapse a device label onto the `cpu`/`gpu` axis the preference is
/// expressed in.
///
/// Everything a client sets is a preference; everything the daemon records as
/// *actual* is the accelerator that preference resolved to. The two are only
/// comparable here — `remote` and anything unrecognized stay themselves, since
/// neither is a local accelerator that a `gpu` preference could have produced.
#[must_use]
pub fn preference_axis(device: &str) -> &str {
    match device {
        "cuda" | "rocm" | "metal" | "vulkan" => "gpu",
        other => other,
    }
}

/// Whether a requested device switch is already in effect, and so has nothing
/// to do.
///
/// The actual device is compared on the preference axis, because it is the
/// accelerator the preference resolved to: a `gpu` request against a daemon
/// already running on `cuda` is asking for what it already has, and reloading
/// the model to grant it costs tens of seconds and a full VRAM churn for no
/// change. A `gpu` preference that fell back to `cpu` still differs, so it is
/// retried — which is the point of tracking preferred and actual separately.
#[must_use]
pub fn switch_is_satisfied(current_preferred: &str, current_actual: &str, requested: &str) -> bool {
    current_preferred == requested && preference_axis(current_actual) == requested
}

/// The message a completed device switch reports.
///
/// Only a GPU request that genuinely landed on the CPU is a fallback; one that
/// landed on an accelerator did exactly what was asked, whatever that
/// accelerator is called.
#[must_use]
pub fn device_switch_message(requested: &str, actual_device: &str) -> String {
    if requested == "gpu" && preference_axis(actual_device) == "cpu" {
        "Device switch requested to GPU, but fell back to CPU: no usable accelerator".to_string()
    } else {
        format!("Successfully switched to {actual_device} device")
    }
}

/// The devices this host can offer.
///
/// Answers for the host, not for any one model: a client narrowing to a
/// specific model intersects this with that model's `supported_devices` and
/// the backend's `installed_accel` from `GET /backend/list`.
#[must_use]
pub fn host_available_devices(host: &Host) -> Vec<String> {
    let mut devices = vec!["cpu".to_string()];
    if host.cuda.is_some() || host.rocm.is_some() || host.vulkan.is_some() || host.metal.is_some() {
        devices.push("gpu".to_string());
    }
    devices
}

/// The devices this install can offer a model on this host.
///
/// `declared` is what the *model* can do, `installed_accel` what the
/// *installed build* can do, and `host_devices` what the machine has; only
/// the intersection is offerable. A CUDA-only backend on a host with no
/// NVIDIA GPU installs its CPU asset, and offering a GPU there is the defect
/// this closes. An empty `installed_accel` means the daemon has no record —
/// a local-directory import, an install predating the record, or a WASM
/// component, whose record names a transport rather than an accelerator —
/// and the manifest is then the only available answer. Online models
/// (`none`) offer nothing: there is no local compute.
#[must_use]
pub fn model_available_devices(
    host_devices: &[String],
    declared: &[Device],
    installed_accel: &[String],
) -> Vec<String> {
    if declared.contains(&Device::None) {
        return Vec::new();
    }
    let installed_accel: Vec<&String> = installed_accel.iter().filter(|a| *a != "wasm").collect();
    let accelerated =
        installed_accel.is_empty() || installed_accel.iter().any(|a| a.as_str() != "cpu");
    let mut offered: Vec<String> = declared
        .iter()
        .map(ToString::to_string)
        .filter(|d| host_devices.contains(d))
        .filter(|d| d == "cpu" || accelerated)
        .collect();
    offered.dedup();
    offered
}

/// The devices a backend can be run on here: the union of what its models
/// are offered, in the `cpu`, `gpu` order every device list uses.
#[must_use]
pub fn backend_available_devices(per_model: impl IntoIterator<Item = Vec<String>>) -> Vec<String> {
    let mut devices: Vec<String> = per_model.into_iter().flatten().collect();
    devices.sort();
    devices.dedup();
    devices
}

/// Why a model cannot be set to `device` at all, or `None` when it can.
///
/// Only the manifest is consulted: an online model has no local device, and
/// a model declaring only `cpu` cannot be sent to the GPU. Whether *this
/// host* has the accelerator is deliberately not a rejection — a `gpu`
/// choice on a host without one falls back to the CPU at load time, reported
/// through `resolved_accel`, the same as it always has. A daemon answers the
/// message as its `invalid_device` error.
#[must_use]
pub fn device_rejection<M>(definition: &ModelDefinition<M>, device: &str) -> Option<String> {
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
    if declared.iter().any(|d| d == device) {
        return None;
    }
    Some(format!(
        "Model {name} does not run on {device}; it supports {}.",
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

    /// The list used to be a constant `["cpu", "cuda"]`, which offered an AMD
    /// host a device it could never resolve. It answers from the probe now.
    #[test]
    fn a_host_without_an_accelerator_offers_only_the_cpu() {
        assert_eq!(
            host_available_devices(&bare_host()),
            vec!["cpu".to_string()]
        );
    }

    #[test]
    fn any_accelerator_adds_the_gpu() {
        let mut cuda = bare_host();
        cuda.cuda = Some(CudaHost {
            compute_capability: 86,
            runtime_major: 13,
            cudnn_present: false,
        });
        assert_eq!(
            host_available_devices(&cuda),
            vec!["cpu".to_string(), "gpu".to_string()]
        );

        let mut vulkan = bare_host();
        vulkan.vulkan = Some(VulkanHost {
            api_version: gpu_probe::VulkanVersion::new(1, 3, 0),
        });
        assert_eq!(
            host_available_devices(&vulkan),
            vec!["cpu".to_string(), "gpu".to_string()]
        );

        // Metal is the accelerator on every Mac, so a daemon that left it out
        // here would offer a Mac the CPU and nothing else — the same bug the
        // hardcoded `["cpu", "cuda"]` list had for AMD.
        let mut metal = bare_host();
        metal.metal = Some(MetalHost);
        assert_eq!(
            host_available_devices(&metal),
            vec!["cpu".to_string(), "gpu".to_string()]
        );
    }

    #[test]
    fn the_wire_setter_accepts_the_deprecated_spellings_and_rejects_junk() {
        assert_eq!(parse_device_preference("gpu"), Some("gpu".to_string()));
        assert_eq!(parse_device_preference("cuda"), Some("gpu".to_string()));
        assert_eq!(parse_device_preference("metal"), Some("gpu".to_string()));
        assert_eq!(parse_device_preference("cpu"), Some("cpu".to_string()));
        assert_eq!(
            parse_device_preference("rocm"),
            None,
            "an accel is not a device"
        );
        assert_eq!(parse_device_preference("none"), None, "not a preference");
        assert_eq!(parse_device_preference("nonsense"), None);
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

    /// A GPU whose driver reports no target — an Apple or Intel part, or an
    /// AMD card on a kernel without KFD — is `null`, never a placeholder
    /// string a client would have to know to ignore.
    #[test]
    fn an_unreported_architecture_is_null() {
        assert_eq!(arch_label(None), None);
    }

    /// A `gpu` preference and the accelerator it resolved to are the same
    /// choice spelled on two axes. Comparing them raw makes the early return
    /// unreachable on every GPU host, so a model switch that stages `gpu`
    /// against a daemon already on CUDA unloads the running model and reloads
    /// it on the same GPU — tens of seconds and a full VRAM churn — before the
    /// model switch it was asked for even begins.
    #[test]
    fn a_switch_to_the_accelerator_already_in_use_has_nothing_to_do() {
        for actual in ["cuda", "rocm", "metal", "vulkan", "gpu"] {
            assert!(
                switch_is_satisfied("gpu", actual, "gpu"),
                "gpu preference already resolved to {actual}"
            );
        }
        assert!(switch_is_satisfied("cpu", "cpu", "cpu"));
    }

    /// The deliberate exception the mapping must preserve: a `gpu` preference
    /// that fell back to the CPU is *not* satisfied, so asking for it again
    /// forces the retry.
    #[test]
    fn a_gpu_preference_that_fell_back_to_the_cpu_is_retried() {
        assert!(!switch_is_satisfied("gpu", "cpu", "gpu"));
        assert!(!switch_is_satisfied("cpu", "cpu", "gpu"));
        assert!(!switch_is_satisfied("gpu", "cuda", "cpu"));
    }

    /// A GPU switch that landed on an accelerator succeeded; reporting a
    /// fallback to CPU on every working GPU host tells the user their machine
    /// failed when it did exactly what they asked.
    #[test]
    fn a_successful_gpu_switch_does_not_report_a_fallback() {
        for actual in ["cuda", "rocm", "metal", "vulkan"] {
            assert_eq!(
                device_switch_message("gpu", actual),
                format!("Successfully switched to {actual} device"),
                "resolved to {actual}"
            );
        }
        assert_eq!(
            device_switch_message("cpu", "cpu"),
            "Successfully switched to cpu device"
        );
    }

    /// A GPU switch that really did land on the CPU still says so.
    #[test]
    fn a_gpu_switch_that_fell_back_says_so() {
        assert_eq!(
            device_switch_message("gpu", "cpu"),
            "Device switch requested to GPU, but fell back to CPU: no usable accelerator"
        );
    }

    /// The mapping itself: every resolved accelerator collapses onto `gpu`,
    /// and nothing else moves.
    #[test]
    fn every_accelerator_collapses_onto_the_gpu_preference() {
        for accel in ["cuda", "rocm", "metal", "vulkan"] {
            assert_eq!(preference_axis(accel), "gpu", "{accel}");
        }
        assert_eq!(preference_axis("gpu"), "gpu");
        assert_eq!(preference_axis("cpu"), "cpu");
        assert_eq!(preference_axis("remote"), "remote");
        assert_eq!(preference_axis("unknown"), "unknown");
    }

    fn both() -> Vec<String> {
        vec!["cpu".to_string(), "gpu".to_string()]
    }

    /// The narrowing that makes a per-model list worth asking for: a model
    /// declaring `gpu` on a backend whose installed asset is CPU-only can run
    /// on no GPU here, whatever the host has.
    #[test]
    fn a_cpu_only_install_offers_no_gpu() {
        assert_eq!(
            model_available_devices(&both(), &[Device::Cpu, Device::Gpu], &["cpu".to_string()]),
            vec!["cpu".to_string()]
        );
        assert_eq!(
            model_available_devices(&both(), &[Device::Gpu], &["cpu".to_string()]),
            Vec::<String>::new(),
            "a GPU-only model on a CPU-only install runs nowhere"
        );
    }

    /// A GPU install on a GPU host offers what the model declares, and the
    /// host list still caps it: no GPU on the host, no GPU offered, even with
    /// a GPU asset installed.
    #[test]
    fn the_host_caps_what_the_install_can_offer() {
        let cuda = vec!["cuda".to_string()];
        assert_eq!(
            model_available_devices(&both(), &[Device::Cpu, Device::Gpu], &cuda),
            both()
        );
        assert_eq!(
            model_available_devices(&["cpu".to_string()], &[Device::Cpu, Device::Gpu], &cuda),
            vec!["cpu".to_string()]
        );
        assert_eq!(
            model_available_devices(&both(), &[Device::Cpu], &cuda),
            vec!["cpu".to_string()],
            "a CPU-only model is not offered the GPU"
        );
    }

    /// No record, or a WASM record naming a transport rather than an
    /// accelerator, leaves the manifest as the only answer.
    #[test]
    fn without_an_accelerator_record_the_manifest_answers() {
        assert_eq!(
            model_available_devices(&both(), &[Device::Cpu, Device::Gpu], &[]),
            both()
        );
        assert_eq!(
            model_available_devices(&both(), &[Device::Cpu, Device::Gpu], &["wasm".to_string()]),
            both()
        );
    }

    /// An online model has no local device to offer.
    #[test]
    fn an_online_model_offers_nothing() {
        assert_eq!(
            model_available_devices(&both(), &[Device::None], &[]),
            Vec::<String>::new()
        );
    }

    /// A backend's list is the union of its models' lists: a CPU-only model
    /// beside a GPU-capable one gives both, an online model contributes
    /// nothing, and the order is always `cpu` then `gpu`.
    #[test]
    fn a_backends_devices_are_the_union_of_its_models() {
        assert_eq!(
            backend_available_devices([
                vec!["gpu".to_string()],
                vec!["cpu".to_string()],
                Vec::new(),
                both(),
            ]),
            both()
        );
        assert_eq!(
            backend_available_devices([Vec::new(), Vec::new()]),
            Vec::<String>::new(),
            "a backend of online models runs on nothing local"
        );
        assert_eq!(backend_available_devices([]), Vec::<String>::new());
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
    /// to: the host's accelerators are a load-time fallback, not a rejection.
    #[test]
    fn a_model_is_refused_only_what_its_manifest_rules_out() {
        let local = definition(vec![Device::Cpu, Device::Gpu]);
        assert!(device_rejection(&local, "cpu").is_none());
        assert!(device_rejection(&local, "gpu").is_none());

        let cpu_only = definition(vec![Device::Cpu]);
        assert!(device_rejection(&cpu_only, "cpu").is_none());
        let rejection = device_rejection(&cpu_only, "gpu").expect("refused");
        assert!(rejection.contains("supports cpu"), "{rejection}");

        let online = definition(vec![Device::None]);
        for device in ["cpu", "gpu"] {
            let rejection = device_rejection(&online, device).expect("refused");
            assert!(rejection.contains("remote service"), "{rejection}");
        }
    }
}
