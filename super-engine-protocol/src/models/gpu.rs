// SPDX-License-Identifier: GPL-3.0-only
//! What `GET /gpu_info` reports: the GPUs a daemon found, and the GPU
//! runtimes installed on the host.

use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
/// One GPU as reported by `GET /gpu_info`.
/// `vendor` is a lowercase `snake_case` tag (`nvidia` / `amd` / `intel` /
/// `apple` / `unknown`). `total_bytes` is dedicated VRAM for discrete GPUs and
/// the shared system-memory ceiling for integrated/unified GPUs;
/// `free_bytes` / `used_bytes` are `null` when the platform doesn't report them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuInfo {
    pub name: String,
    pub vendor: String,
    pub total_bytes: u64,
    #[serde(default)]
    pub free_bytes: Option<u64>,
    #[serde(default)]
    pub used_bytes: Option<u64>,
    /// The architecture a prebuilt asset must target to run on this GPU, in
    /// the vendor's own spelling: `"sm_86"` on NVIDIA, `"gfx1030"` on AMD.
    /// `null` when the driver reports none (an Apple or Intel GPU, or an AMD
    /// card on a kernel without KFD).
    #[serde(default)]
    pub arch_target: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
/// Host-wide GPU toolchain/driver versions reported on
/// `GET /gpu_info`, independent
/// of any one GPU. Each field is `null` when that accelerator's runtime isn't
/// detected on this host. Presence says the runtime is installed, not that a
/// GPU is behind it: a caller wanting that reads the GPUs themselves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GpuHostInfo {
    #[serde(default)]
    pub cuda: Option<CudaHostInfo>,
    #[serde(default)]
    pub rocm: Option<RocmHostInfo>,
    #[serde(default)]
    pub vulkan: Option<VulkanHostInfo>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
/// The installed NVIDIA driver's CUDA version, e.g. `"13.3"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CudaHostInfo {
    pub driver_version: String,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
/// The installed `ROCm` userspace release, e.g. `"6.2.4"`. Advisory only:
/// [`GpuInfo::arch_target`] is what a build must actually match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RocmHostInfo {
    pub version: String,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
/// The highest Vulkan API version any installed driver advertises, e.g.
/// `"1.3.280"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulkanHostInfo {
    pub api_version: String,
}
