// SPDX-License-Identifier: GPL-3.0-only
//! `select(daemon, host, entry)` and `select_files(host, model)` — pure: no
//! I/O, no shared state. Both are driven solely by host capability (the most
//! optimal candidate the host can run); the runtime device preference is
//! intentionally decoupled and never affects what is downloaded.
//!
//! The two answer the same question about two kinds of candidate — which build
//! of the backend to install, and which variant of a model file to fetch — so
//! they share one ranking ([`score`]) over one normalized shape
//! ([`Requires`]). This is also the one place the manifest's architecture
//! vocabulary (`super_engine_spec::arch`) meets `gpu_probe`'s.
//!
//! Before any of that, [`select`] asks whether the daemon can drive the
//! entry's contract generation at all: an entry it cannot is refused as
//! [`Selection::NeedsClientUpdate`], whatever the host.

use semver::Version;
use super_engine_spec::arch::{GfxSpec, VulkanApi};
use super_engine_spec::index::{IndexBackend, IndexSubprocessAsset};
use super_engine_spec::manifest::{Accel, FileSpec, ModelEntry};
use super_engine_spec::product::Product;
use super_engine_spec::registry::SelectedAsset;

use crate::registry::Daemon;
use crate::registry::host::Host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Wasm,
    Subprocess {
        index: usize,
    },
    Incompatible {
        reason: String,
    },
    /// This build does not know the entry's contract generation. Distinct
    /// from [`Incompatible`](Self::Incompatible) because the remedy is
    /// different in kind: a host that lacks the right GPU will never run this
    /// asset, but a daemon that is merely too old is one update away — so
    /// clients surface this even where they hide hardware mismatches.
    NeedsClientUpdate {
        reason: String,
    },
}

impl Selection {
    /// The human-readable reason this entry cannot be installed, or `None`
    /// when it can.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Wasm | Self::Subprocess { .. } => None,
            Self::Incompatible { reason } | Self::NeedsClientUpdate { reason } => Some(reason),
        }
    }

    /// Whether the block is "this daemon is too old" rather than "this
    /// machine cannot run it".
    #[must_use]
    pub fn needs_client_update(&self) -> bool {
        matches!(self, Self::NeedsClientUpdate { .. })
    }
}

/// Below this major version an AMD architecture's *stepping* is a whole
/// generation rather than a variant, so the same-family fallback must not
/// apply. `gfx900` (Vega 10), `gfx906` (Vega 20), `gfx908` (MI100) and
/// `gfx90a` (MI200) all decode to major 9, minor 0 and are mutually
/// incompatible; from `gfx10` on, steppings within a minor are ISA-compatible,
/// which is what makes one `gfx1030` build serve the whole `gfx103x` line.
pub const GFX_FAMILY_FLOOR: u32 = 10;

/// Rank of an accel family. A native accel beats a portable one, which beats
/// the CPU, which beats a candidate that named no requirement at all. CUDA and
/// `ROCm` never compete: a host reports a compute capability or gfx targets,
/// not both.
///
/// [`RANK_ANY`] exists only for `[[models.files]]`: an entry with no selector
/// is every v1 file, it runs anywhere, and it must lose to any sibling variant
/// that named this host — it is the fallback, not a peer. No asset can hold it,
/// since `Manifest::parse` refuses an empty `accel` on a build.
const RANK_ANY: u8 = 0;
const RANK_CPU: u8 = 1;
const RANK_VULKAN: u8 = 2;
const RANK_NATIVE: u8 = 3;

/// Whether an asset's declared gfx target can run on a host's.
///
/// Exact always; same-family only from [`GFX_FAMILY_FLOOR`] up.
fn gfx_runs_on(asset: GfxSpec, host: gpu_probe::GfxTarget) -> bool {
    gfx_is_exact(asset, host)
        || (asset.major >= GFX_FAMILY_FLOOR
            && asset.major == host.major
            && asset.minor == host.minor)
}

/// Whether an asset's declared gfx target is an exact hit, used to rank an
/// exact match above one that relied on the family fallback.
fn gfx_is_exact(asset: GfxSpec, host: gpu_probe::GfxTarget) -> bool {
    asset.major == host.major && asset.minor == host.minor && asset.step == host.step
}

/// Longest registry-supplied contract string echoed into a reason. A
/// generation is `v` plus digits; anything longer is not one, and the reason
/// is user-facing text assembled from a document this daemon did not write.
const MAX_ECHOED_CONTRACT: usize = 16;

/// Why an entry's contract generation cannot be driven by this daemon, or
/// `None` when it can.
///
/// The generation is the one thing a manifest declares about what it needs
/// from a daemon, and a daemon knows every generation up to the one it was
/// built with — so "does the string parse as the product's
/// [`Product::Contract`]" is the whole
/// test. The index also stamps the release that introduced the generation, so
/// the reason can say what to update to even for a generation this build has
/// never heard of.
///
/// Both echoed values come from `index.json`, which is fetched — and the
/// product's `REGISTRY_URL` variable can point somewhere else, which is why
/// `retain_safe_backends` already sanitizes the fields that become paths.
/// These two only become text, so they are bounded rather than rejected: the
/// contract is truncated, and `min_client` is quoted only when it parses as
/// semver *and* actually exceeds this build. A floor at or below the running
/// version would otherwise produce advice the user has already followed.
fn contract_block<P: Product>(
    daemon: &Daemon,
    entry: &IndexBackend<P::IndexModel>,
) -> Option<String> {
    if entry.contract.parse::<P::Contract>().is_ok() {
        return None;
    }
    let product = daemon.product.display_name;
    let daemon = daemon.version;
    let contract: String = entry.contract.chars().take(MAX_ECHOED_CONTRACT).collect();
    let floor = entry.min_client.as_deref().filter(|min| {
        match (Version::parse(min), Version::parse(daemon)) {
            (Ok(min), Ok(running)) => min > running,
            _ => false,
        }
    });
    Some(match floor {
        Some(min) => {
            format!(
                "needs {product} {min} or newer (backend contract {contract}); this is {daemon}"
            )
        }
        None => format!("needs a newer {product} (backend contract {contract}); this is {daemon}"),
    })
}

/// Which build of `entry` this host should install, for a `daemon` of product
/// `P`.
#[must_use]
pub fn select<P: Product>(
    daemon: &Daemon,
    host: &Host,
    entry: &IndexBackend<P::IndexModel>,
) -> Selection {
    // Before any asset question: a backend this daemon cannot drive has no
    // compatible asset, whatever the host looks like. Listing, install and
    // update all route through here, so one check covers all three.
    if let Some(reason) = contract_block::<P>(daemon, entry) {
        return Selection::NeedsClientUpdate { reason };
    }
    if entry.kind == "wasm" {
        return if entry.assets.wasm.is_some() {
            Selection::Wasm
        } else {
            Selection::Incompatible {
                reason: "wasm backend missing wasm asset".into(),
            }
        };
    }
    if entry.kind != "subprocess" {
        return Selection::Incompatible {
            reason: format!("unknown kind `{}`", entry.kind),
        };
    }
    // Filter by target triple.
    let by_target: Vec<(usize, &IndexSubprocessAsset)> = entry
        .assets
        .subprocess
        .iter()
        .enumerate()
        .filter(|(_, a)| a.target == host.target_triple)
        .collect();
    if by_target.is_empty() {
        return Selection::Incompatible {
            reason: format!("no asset for target `{}`", host.target_triple),
        };
    }

    // Capability-driven: the most optimal asset the host can run. Independent
    // of the runtime device preference — a GPU build still runs on CPU when
    // the user selects that device.
    // `reduce` keeping a strict improvement, not `max_by_key`: that returns the
    // *last* maximum. First-wins is the intended tiebreak — an asset's position
    // in the manifest is the author's own preference order, and the CPU
    // fallback already behaved this way as a `.find()`. It does change the CUDA
    // path, which used `max_by_key` and so resolved a tie to the *last*
    // declared asset; nothing pinned that, and one rule across every accel is
    // worth more than preserving an accident on one of them.
    let best = by_target
        .iter()
        .filter_map(|(idx, a)| score(host, &Requires::from(*a)).map(|s| (s, *idx)))
        .reduce(|best, next| if next.0 > best.0 { next } else { best });
    if let Some((_, idx)) = best {
        return Selection::Subprocess { index: idx };
    }
    Selection::Incompatible {
        reason: incompatible_reason(host, &by_target),
    }
}

/// What one candidate requires of the host, normalized out of whichever
/// vocabulary it was written in: the free-form strings of an index entry, or
/// the parsed types of a manifest's `[[models.files]]`.
///
/// One shape so [`score`] can be one policy. Picking a build and picking a
/// per-architecture model file ask the same question of the same host, and a
/// second copy of the answer would drift from this one the first time either
/// changed.
#[derive(Debug, Default)]
struct Requires {
    accel: Vec<Accel>,
    cuda_major: Option<u32>,
    /// The compute capabilities the candidate covers; empty is "any". An asset
    /// contributes at most one, a file any number.
    cuda_sm: Vec<u32>,
    cudnn: bool,
    gfx: Vec<GfxSpec>,
    vulkan_api: Option<VulkanApi>,
    /// A `vulkan_api` that was written but did not parse, kept apart from
    /// `None` so [`score`] can fail closed on it.
    vulkan_api_malformed: bool,
    /// Whether a missing family discriminator — no `cuda_major`, no `gfx` —
    /// reads as "any host of that family" or as "nothing".
    ///
    /// True for a `[[models.files]]` variant: `Manifest::parse` lets a file
    /// declare `cuda` without a runtime major and `rocm` without a target,
    /// because a file is data whose meaning belongs to the backend, and "for
    /// any CUDA host" is a thing it can honestly say.
    ///
    /// False for an index asset, and not for symmetry's sake: the index is
    /// *not* validated by `Manifest::parse`, so a published entry can carry
    /// the same shape by accident. A build must name the runtime it links and
    /// the ISA it was compiled for, so an entry naming neither has to match
    /// nothing rather than everything — see
    /// `cuda_asset_without_cuda_major_falls_back_to_cpu`.
    wildcard_when_absent: bool,
}

/// An index entry carries `accel` as free-form strings, so one published by a
/// newer registry may name a family this build has no word for. Dropping it is
/// what the string comparisons here did before `Requires` existed: an unknown
/// family matches nothing and stays out of the way of the ones that do.
fn parse_accel(text: &str) -> Option<Accel> {
    match text {
        "cpu" => Some(Accel::Cpu),
        "cuda" => Some(Accel::Cuda),
        "metal" => Some(Accel::Metal),
        "rocm" => Some(Accel::Rocm),
        "vulkan" => Some(Accel::Vulkan),
        _ => None,
    }
}

impl From<&IndexSubprocessAsset> for Requires {
    fn from(a: &IndexSubprocessAsset) -> Self {
        let (vulkan_api, vulkan_api_malformed) = match a.vulkan_api.as_deref() {
            None => (None, false),
            Some(floor) => match floor.parse::<VulkanApi>() {
                Ok(v) => (Some(v), false),
                Err(_) => (None, true),
            },
        };
        Self {
            accel: a
                .accel
                .iter()
                .map(String::as_str)
                .filter_map(parse_accel)
                .collect(),
            cuda_major: a.cuda_major,
            cuda_sm: a.cuda_sm.into_iter().collect(),
            cudnn: a.cudnn,
            // A gfx target that does not parse drops out rather than widening
            // the match, the same way an unknown accel does.
            gfx: a.gfx.iter().filter_map(|g| g.parse().ok()).collect(),
            vulkan_api,
            vulkan_api_malformed,
            wildcard_when_absent: false,
        }
    }
}

impl From<&FileSpec> for Requires {
    /// A manifest's values are already parsed, so nothing here can be
    /// malformed — the strings were rejected at `Manifest::parse`.
    fn from(f: &FileSpec) -> Self {
        Self {
            accel: f.accel.clone(),
            cuda_major: f.cuda_major,
            cuda_sm: f.cuda_sm.clone(),
            cudnn: false,
            gfx: f.gfx.clone(),
            vulkan_api: f.vulkan_api,
            vulkan_api_malformed: false,
            wildcard_when_absent: true,
        }
    }
}

/// Rank a candidate against the host, or `None` when the host cannot use it.
///
/// The tuple orders lexicographically, which is the whole preference policy:
/// accel family first, then the family's own discriminators.
///
/// Two arms read a missing discriminator as "any" for a candidate that set
/// [`Requires::wildcard_when_absent`], which is every `[[models.files]]`
/// variant and no asset. Both are called out where they happen.
fn score(host: &Host, r: &Requires) -> Option<(u8, u32, u8, u8)> {
    let declares = |k: Accel| r.accel.contains(&k);

    if declares(Accel::Cuda)
        && let Some(cuda) = &host.cuda
        && (r.cuda_sm.is_empty() || r.cuda_sm.contains(&cuda.compute_capability))
        // An absent `cuda_major` is "any CUDA runtime" for a file, and a
        // malformed asset for an index entry — which is why the wildcard is
        // conditional rather than folded into the comparison.
        && (r.cuda_major.is_some_and(|m| m <= cuda.runtime_major)
            || (r.wildcard_when_absent && r.cuda_major.is_none()))
    {
        return Some((
            RANK_NATIVE,
            r.cuda_major.unwrap_or(0),
            u8::from(!r.cuda_sm.is_empty()),
            u8::from(r.cudnn && cuda.cudnn_present),
        ));
    }

    if declares(Accel::Rocm)
        && let Some(rocm) = &host.rocm
    {
        if r.gfx.is_empty() {
            // "Any AMD host" for a file, ranked with the inexact matches below
            // so a variant naming this host's architecture still wins. For an
            // asset it is a target list that named nothing, which matches
            // nothing — fall through to whatever else it declares.
            if r.wildcard_when_absent {
                return Some((RANK_NATIVE, 0, 0, 0));
            }
        } else {
            let mut best: Option<u8> = None;
            for host_target in &rocm.gfx_targets {
                for want in &r.gfx {
                    if gfx_runs_on(*want, *host_target) {
                        let exact = u8::from(gfx_is_exact(*want, *host_target));
                        best = Some(best.map_or(exact, |b| b.max(exact)));
                    }
                }
            }
            if let Some(exact) = best {
                return Some((RANK_NATIVE, 0, exact, 0));
            }
        }
    }

    if declares(Accel::Vulkan)
        && let Some(vulkan) = &host.vulkan
    {
        // A declared floor that does not parse fails closed — the candidate
        // stops matching, exactly as a bad gfx string drops out of `gfx` in
        // `Requires`. The natural authoring mistake is `vulkan_api = "1.3.0"`,
        // natural because `VulkanApi` has no patch component, and folding that
        // into "no floor declared" would match every Vulkan host including a
        // 1.0 one that cannot run the build. Falling through rather than
        // returning leaves any other accel the candidate declares free to
        // match.
        let ok = !r.vulkan_api_malformed
            && r.vulkan_api.is_none_or(|f| {
                (vulkan.api_version.major, vulkan.api_version.minor) >= (f.major, f.minor)
            });
        if ok {
            return Some((RANK_VULKAN, 0, 0, 0));
        }
    }

    // Metal has no discriminator to compare — a candidate either declares it
    // or does not, and the host either has it or does not (see
    // `host::MetalHost`). Ranked `RANK_NATIVE` alongside CUDA and ROCm, and
    // for the same reason: on the hardware it targets it is the vendor's own
    // path to the GPU, not a portable abstraction over one.
    if declares(Accel::Metal) && host.metal.is_some() {
        return Some((RANK_NATIVE, 0, 0, 0));
    }

    if declares(Accel::Cpu) {
        return Some((RANK_CPU, 0, 0, 0));
    }
    None
}

/// The `Incompatible` reason: what this host offers, and what the candidate
/// builds asked for.
///
/// Both halves are needed. The host's capability alone names whichever axis
/// happened to match and stays silent about the one that failed — an `sm_86`
/// host offered a `cuda_major = 13` build is told `sm_86`, which is true and
/// useless, since its card *is* `sm_86`. Naming what the candidates require
/// turns "here is my host" into something a backend author can act on.
///
/// Only assets already filtered to this target triple reach here, so the
/// requirement list describes real alternatives rather than every asset
/// published.
fn incompatible_reason(host: &Host, candidates: &[(usize, &IndexSubprocessAsset)]) -> String {
    let host_caps = host_capabilities(host);
    let mut wants: Vec<String> = Vec::new();
    for (_, a) in candidates {
        let want = asset_requirement(a);
        if !wants.contains(&want) {
            wants.push(want);
        }
    }
    if wants.is_empty() {
        format!(
            "no compatible asset for host `{}`: {host_caps}",
            host.target_triple
        )
    } else {
        format!(
            "no compatible asset for host `{}`: {host_caps} — candidate builds require: {}",
            host.target_triple,
            wants.join(", ")
        )
    }
}

/// What this host offers, for the message a user reads when nothing matched.
///
/// Shared by the two refusals — no installable build, and no usable variant of
/// a required model file — because they are the same sentence about the same
/// machine, and a user comparing them should not have to reconcile two
/// spellings of one GPU.
fn host_capabilities(host: &Host) -> String {
    let mut caps = Vec::new();
    if let Some(c) = &host.cuda {
        // The runtime major is reported alongside the SM because it is the
        // axis that excludes a build the card itself could have run.
        caps.push(format!(
            "sm_{}, CUDA {}",
            c.compute_capability, c.runtime_major
        ));
    }
    if let Some(r) = &host.rocm {
        let targets: Vec<String> = r.gfx_targets.iter().map(ToString::to_string).collect();
        // The userspace version is diagnostic only — it never gated selection,
        // but it is the first thing to check when a ROCm asset was expected.
        match r.version {
            Some(v) => caps.push(format!("{} (ROCm {v})", targets.join(","))),
            None => caps.push(format!("{} (no ROCm userspace found)", targets.join(","))),
        }
    }
    if let Some(v) = &host.vulkan {
        caps.push(format!("vulkan {}", v.api_version));
    }
    if host.metal.is_some() {
        caps.push("metal".into());
    }
    if caps.is_empty() {
        caps.push("cpu only".into());
    }
    caps.join("; ")
}

/// What one candidate asset needs, in the vocabulary its manifest declares it
/// in, so the requirement reads back as the field the author would edit.
fn asset_requirement(a: &IndexSubprocessAsset) -> String {
    let mut parts = Vec::new();
    for accel in &a.accel {
        parts.push(match accel.as_str() {
            "cuda" => {
                let major = a
                    .cuda_major
                    .map_or_else(|| "?".to_string(), |m| m.to_string());
                let sm = a.cuda_sm.map_or_else(|| "*".to_string(), |s| s.to_string());
                format!("cuda {major} sm_{sm}")
            }
            "rocm" => format!("rocm {}", a.gfx.join(",")),
            "vulkan" => match a.vulkan_api.as_deref() {
                Some(v) => format!("vulkan {v}+"),
                None => "vulkan".to_string(),
            },
            other => other.to_string(),
        });
    }
    if parts.is_empty() {
        "an unspecified accel".to_string()
    } else {
        parts.join("+")
    }
}

/// The `[[models.files]]` this host should download for `model`, in the order
/// the manifest declares them.
///
/// Entries sharing a `destination` are variants of one file and are resolved
/// against each other by [`score`]: the best match is downloaded, the rest are
/// not, and the backend reads a fixed path either way. A manifest with no
/// selector anywhere — every v1 manifest — yields its files unchanged, since an
/// unconditional entry matches every host and no destination has a rival.
///
/// Host capability decides, never the user's device preference. That is the
/// rule [`select`] follows for builds, and it matters more here: what is on
/// disk must not change when the user toggles between CPU and GPU, or every
/// such toggle would re-download gigabytes.
///
/// # Errors
/// Returns a human-readable reason when a destination that is not `optional`
/// has no variant this host can use — naming what the host offers and what the
/// variants asked for, the same shape as an incompatible install.
pub fn select_files<'a, M>(
    host: &Host,
    model: &'a ModelEntry<M>,
) -> Result<Vec<&'a FileSpec>, String> {
    let mut chosen: Vec<&FileSpec> = Vec::new();
    let mut resolved: Vec<&str> = Vec::new();

    for entry in &model.files {
        let destination = entry.destination.as_str();
        if resolved.contains(&destination) {
            continue; // already settled with the rest of its group
        }
        resolved.push(destination);

        let variants: Vec<&FileSpec> = model
            .files
            .iter()
            .filter(|f| f.destination == entry.destination)
            .collect();
        // `reduce` keeping a strict improvement, not `max_by_key`: that returns
        // the *last* maximum. First-wins is the tiebreak `select` applies to
        // builds, for the same reason — declaration order is the author's own
        // preference.
        let best = variants
            .iter()
            .filter_map(|f| score_file(host, f).map(|s| (s, *f)))
            .reduce(|best, next| if next.0 > best.0 { next } else { best });

        match best {
            Some((_, file)) => chosen.push(file),
            // `Manifest::parse` makes the variants of one destination agree on
            // `optional`, so `all` and `any` are the same question here; `all`
            // is the one that stays right if they ever disagree.
            None if variants.iter().all(|f| f.optional) => {
                log::info!(
                    "skipping optional {destination}: no variant matches this host ({})",
                    host_capabilities(host)
                );
            }
            None => return Err(unusable_reason(host, destination, &variants)),
        }
    }
    Ok(chosen)
}

/// Rank one file variant, where naming no requirement means "any host".
///
/// [`score`] is deliberately strict about that: an index entry with an empty
/// `accel` is a malformed asset and must not become installable. A file entry
/// with an empty `accel` is the opposite — it is every file every v1 manifest
/// ever declared — so the fallback is applied here, outside the shared policy.
fn score_file(host: &Host, file: &FileSpec) -> Option<(u8, u32, u8, u8)> {
    if file.is_conditional() {
        score(host, &Requires::from(file))
    } else {
        Some((RANK_ANY, 0, 0, 0))
    }
}

/// The refusal for a required destination no variant matched.
fn unusable_reason(host: &Host, destination: &str, variants: &[&FileSpec]) -> String {
    let mut wants: Vec<String> = Vec::new();
    for file in variants {
        let want = file_requirement(file);
        if !wants.contains(&want) {
            wants.push(want);
        }
    }
    format!(
        "no variant of `{destination}` runs on this host: {} — variants require: {}",
        host_capabilities(host),
        wants.join(", ")
    )
}

/// What one file variant needs, in the vocabulary its manifest declares it in
/// — the same courtesy [`asset_requirement`] pays a build, over the typed
/// fields a manifest parses into rather than an index entry's strings.
fn file_requirement(file: &FileSpec) -> String {
    let mut parts = Vec::new();
    for accel in &file.accel {
        parts.push(match accel {
            Accel::Cuda => {
                let major = file
                    .cuda_major
                    .map_or_else(|| "*".to_string(), |m| m.to_string());
                let sm = if file.cuda_sm.is_empty() {
                    "*".to_string()
                } else {
                    let each: Vec<String> = file.cuda_sm.iter().map(ToString::to_string).collect();
                    each.join("/")
                };
                format!("cuda {major} sm_{sm}")
            }
            Accel::Rocm if file.gfx.is_empty() => "rocm".to_string(),
            Accel::Rocm => {
                let targets: Vec<String> = file.gfx.iter().map(ToString::to_string).collect();
                format!("rocm {}", targets.join(","))
            }
            Accel::Vulkan => match file.vulkan_api {
                Some(v) => format!("vulkan {v}+"),
                None => "vulkan".to_string(),
            },
            other => other.to_string(),
        });
    }
    if parts.is_empty() {
        "any host".to_string()
    } else {
        parts.join("+")
    }
}

#[must_use]
pub fn to_selected_asset<M>(entry: &IndexBackend<M>, sel: &Selection) -> Option<SelectedAsset> {
    match sel {
        Selection::Wasm => entry.assets.wasm.as_ref().map(|_| SelectedAsset {
            target: String::new(),
            accel: vec!["wasm".into()],
            cuda_major: None,
            cuda_sm: None,
            cudnn: false,
        }),
        Selection::Subprocess { index } => {
            entry.assets.subprocess.get(*index).map(|a| SelectedAsset {
                target: a.target.clone(),
                accel: a.accel.clone(),
                cuda_major: a.cuda_major,
                cuda_sm: a.cuda_sm,
                cudnn: a.cudnn,
            })
        }
        Selection::Incompatible { .. } | Selection::NeedsClientUpdate { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::host::{CudaHost, Host};
    use super_engine_spec::index::{IndexAsset, IndexAssets};
    use super_engine_spec::product::Generation;
    use super_engine_spec::test_product::{self, Contract, TestProduct};

    type IndexBackend = super_engine_spec::index::IndexBackend<test_product::IndexModel>;

    /// A daemon of the test product at 0.2.0.
    const DAEMON: Daemon = Daemon {
        product: &super_engine_protocol::test_product::TEST,
        version: "0.2.0",
        user_agent: "super-engine-daemon-tests",
    };

    /// [`super::select`] for [`DAEMON`].
    fn select(host: &Host, entry: &IndexBackend) -> Selection {
        super::select::<TestProduct>(&DAEMON, host, entry)
    }

    fn entry(kind: &str, subprocess: Vec<IndexSubprocessAsset>) -> IndexBackend {
        IndexBackend {
            id: "t".into(),
            backend_id: None,
            source: "x".into(),
            version: "1.0.0".into(),
            tag: "v1.0.0".into(),
            name: "T".into(),
            description: None,
            license: "Apache-2.0".into(),
            kind: kind.into(),
            contract: "v1".into(),
            min_client: None,
            entrypoint: "t".into(),
            allowed_hosts: vec![],
            online: false,
            supports_gpu: true,
            supports_cpu: true,
            models: vec![],
            secrets: vec![],
            options: vec![],
            assets: IndexAssets {
                wasm: None,
                subprocess,
            },
            index_stale: None,
            manifest: None,
        }
    }

    fn sp(
        target: &str,
        accel: &str,
        sm: Option<u32>,
        cm: Option<u32>,
        cudnn: bool,
    ) -> IndexSubprocessAsset {
        IndexSubprocessAsset {
            target: target.into(),
            accel: vec![accel.into()],
            cuda_major: cm,
            cuda_sm: sm,
            cudnn,
            gfx: Vec::new(),
            vulkan_api: None,
            url: Some("x".into()),
            size: Some(1),
            sha256: Some("x".into()),
            parts: Vec::new(),
        }
    }

    fn sp_rocm(target: &str, gfx: &[&str]) -> IndexSubprocessAsset {
        IndexSubprocessAsset {
            target: target.into(),
            accel: vec!["rocm".into()],
            cuda_major: None,
            cuda_sm: None,
            cudnn: false,
            gfx: gfx.iter().map(|g| (*g).to_string()).collect(),
            vulkan_api: None,
            url: Some("x".into()),
            size: Some(1),
            sha256: Some("x".into()),
            parts: Vec::new(),
        }
    }

    fn host_rocm(gfx: &[(u32, u32, u32)]) -> Host {
        Host {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            cuda: None,
            rocm: Some(crate::registry::host::RocmHost {
                gfx_targets: gfx
                    .iter()
                    .map(|(a, b, c)| gpu_probe::GfxTarget::new(*a, *b, *c))
                    .collect(),
                version: None,
            }),
            vulkan: None,
            metal: None,
        }
    }

    fn host_cuda(sm: u32, cm: u32, cudnn: bool) -> Host {
        Host {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            cuda: Some(CudaHost {
                compute_capability: sm,
                runtime_major: cm,
                cudnn_present: cudnn,
            }),
            rocm: None,
            vulkan: None,
            metal: None,
        }
    }

    fn host_metal() -> Host {
        Host {
            target_triple: "aarch64-apple-darwin".into(),
            cuda: None,
            rocm: None,
            vulkan: None,
            metal: Some(crate::registry::host::MetalHost),
        }
    }

    fn host_cpu() -> Host {
        Host {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            cuda: None,
            rocm: None,
            vulkan: None,
            metal: None,
        }
    }

    #[test]
    fn cpu_host_without_gpu_picks_cpu() {
        // Capability-driven: with no GPU on the host, the CPU asset is selected
        // even though a matching CUDA asset exists.
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(86),
                    Some(13),
                    false,
                ),
            ],
        );
        let sel = select(&host_cpu(), &e);
        assert_eq!(sel, Selection::Subprocess { index: 0 });
    }

    #[test]
    fn picks_matching_cuda_on_capable_host() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(86),
                    Some(12),
                    false,
                ),
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(90),
                    Some(12),
                    false,
                ),
            ],
        );
        let sel = select(&host_cuda(86, 12, false), &e);
        assert_eq!(sel, Selection::Subprocess { index: 1 });
    }

    #[test]
    fn falls_back_to_cpu_when_no_sm_match() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(90),
                    Some(12),
                    false,
                ),
            ],
        );
        let sel = select(&host_cuda(86, 12, false), &e);
        assert_eq!(sel, Selection::Subprocess { index: 0 });
    }

    #[test]
    fn prefers_cudnn_when_host_has_it() {
        let e = entry(
            "subprocess",
            vec![
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(86),
                    Some(12),
                    false,
                ),
                sp("x86_64-unknown-linux-gnu", "cuda", Some(86), Some(12), true),
            ],
        );
        let sel = select(&host_cuda(86, 12, true), &e);
        assert_eq!(sel, Selection::Subprocess { index: 1 });
    }

    #[test]
    fn picks_highest_cuda_major_within_runtime() {
        let e = entry(
            "subprocess",
            vec![
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(86),
                    Some(12),
                    false,
                ),
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(86),
                    Some(13),
                    false,
                ),
            ],
        );
        // Host has CUDA 13 runtime
        let sel = select(&host_cuda(86, 13, false), &e);
        assert_eq!(sel, Selection::Subprocess { index: 1 });
    }

    #[test]
    fn cuda_runtime_caps_choice() {
        let e = entry(
            "subprocess",
            vec![
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(86),
                    Some(12),
                    false,
                ),
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(86),
                    Some(13),
                    false,
                ),
            ],
        );
        // Host has CUDA 12 runtime — must not pick the cuda_major=13 build.
        let sel = select(&host_cuda(86, 12, false), &e);
        assert_eq!(sel, Selection::Subprocess { index: 0 });
    }

    #[test]
    fn wildcard_cuda_sm_matches_any_compute_capability() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                // No cuda_sm -> wildcard.
                sp("x86_64-unknown-linux-gnu", "cuda", None, Some(13), false),
            ],
        );
        // Host is sm_120 with a CUDA 13 runtime; the wildcard must match.
        let sel = select(&host_cuda(120, 13, false), &e);
        assert_eq!(sel, Selection::Subprocess { index: 1 });
    }

    #[test]
    fn exact_cuda_sm_is_preferred_over_wildcard() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cuda", None, Some(13), false),
                sp(
                    "x86_64-unknown-linux-gnu",
                    "cuda",
                    Some(90),
                    Some(13),
                    false,
                ),
            ],
        );
        let sel = select(&host_cuda(90, 13, false), &e);
        assert_eq!(
            sel,
            Selection::Subprocess { index: 1 },
            "an exact-SM asset must win over a wildcard"
        );
    }

    #[test]
    fn wildcard_cuda_still_respects_runtime_major() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                // Wildcard SM but cuda_major=13 — must NOT match a CUDA 12 host.
                sp("x86_64-unknown-linux-gnu", "cuda", None, Some(13), false),
            ],
        );
        let sel = select(&host_cuda(86, 12, false), &e);
        assert_eq!(
            sel,
            Selection::Subprocess { index: 0 },
            "cuda_major>runtime_major must fall back to CPU"
        );
    }

    #[test]
    fn cuda_asset_without_cuda_major_falls_back_to_cpu() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                // Malformed: cuda accel with neither cuda_sm nor cuda_major.
                // Must not match any host — the cuda_major guard excludes it.
                sp("x86_64-unknown-linux-gnu", "cuda", None, None, false),
            ],
        );
        let sel = select(&host_cuda(86, 12, false), &e);
        assert_eq!(
            sel,
            Selection::Subprocess { index: 0 },
            "a cuda asset with no cuda_major must be ignored, not match every host"
        );
    }

    #[test]
    fn an_exact_gfx_target_matches() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx1030"]),
            ],
        );
        assert_eq!(
            select(&host_rocm(&[(10, 3, 0)]), &e),
            Selection::Subprocess { index: 1 }
        );
    }

    /// Steppings within a minor are ISA-compatible on RDNA — this is the
    /// `HSA_OVERRIDE_GFX_VERSION=10.3.0` practice that makes one gfx1030 build
    /// serve the whole gfx103x line.
    #[test]
    fn a_same_family_gfx_target_matches_on_rdna() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx1030"]),
            ],
        );
        assert_eq!(
            select(&host_rocm(&[(10, 3, 1)]), &e),
            Selection::Subprocess { index: 1 },
            "gfx1031 must take the gfx1030 build"
        );
        let e11 = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx1100"]),
            ],
        );
        assert_eq!(
            select(&host_rocm(&[(11, 0, 1)]), &e11),
            Selection::Subprocess { index: 1 },
            "gfx1101 must take the gfx1100 build"
        );
    }

    /// On CDNA and Vega the *step* is a whole generation: gfx900 (Vega 10),
    /// gfx906 (Vega 20), gfx908 (MI100) and gfx90a (MI200) all decode to
    /// major 9, minor 0 while being mutually incompatible. An unguarded
    /// family rule would hand an MI100 an MI200 build.
    #[test]
    fn the_family_fallback_does_not_apply_to_gfx9() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx90a"]),
            ],
        );
        assert_eq!(
            select(&host_rocm(&[(9, 0, 8)]), &e),
            Selection::Subprocess { index: 0 },
            "an MI100 must fall back to CPU, never take an MI200 build"
        );
        assert_eq!(
            select(&host_rocm(&[(9, 0, 10)]), &e),
            Selection::Subprocess { index: 1 },
            "an exact gfx90a match is still fine"
        );
    }

    #[test]
    fn an_exact_gfx_match_outranks_a_family_match() {
        let e = entry(
            "subprocess",
            vec![
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx1030"]),
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx1031"]),
            ],
        );
        assert_eq!(
            select(&host_rocm(&[(10, 3, 1)]), &e),
            Selection::Subprocess { index: 1 }
        );
    }

    #[test]
    fn a_rocm_host_with_no_matching_gfx_falls_back_to_cpu() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx1100"]),
            ],
        );
        assert_eq!(
            select(&host_rocm(&[(10, 3, 0)]), &e),
            Selection::Subprocess { index: 0 }
        );
    }

    /// Declaration order breaks a tie. The CPU fallback used to be a `.find()`,
    /// so the first matching asset won; scoring must not quietly move that to
    /// the last one.
    #[test]
    fn equally_ranked_assets_resolve_to_the_first_declared() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
            ],
        );
        assert_eq!(select(&host_cpu(), &e), Selection::Subprocess { index: 0 });
    }

    #[test]
    fn a_dual_runtime_asset_matches_on_either_host() {
        let mut dual = sp_rocm("x86_64-unknown-linux-gnu", &["gfx1030"]);
        dual.accel = vec!["cuda".into(), "rocm".into()];
        dual.cuda_major = Some(12);
        dual.cuda_sm = Some(86);
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                dual,
            ],
        );
        assert_eq!(
            select(&host_cuda(86, 12, false), &e),
            Selection::Subprocess { index: 1 }
        );
        assert_eq!(
            select(&host_rocm(&[(10, 3, 0)]), &e),
            Selection::Subprocess { index: 1 }
        );
    }

    #[test]
    fn a_native_accel_outranks_vulkan_which_outranks_cpu() {
        let mut vk = sp("x86_64-unknown-linux-gnu", "cpu", None, None, false);
        vk.accel = vec!["vulkan".into()];
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
                vk.clone(),
                sp_rocm("x86_64-unknown-linux-gnu", &["gfx1030"]),
            ],
        );
        let mut host = host_rocm(&[(10, 3, 0)]);
        host.vulkan = Some(crate::registry::host::VulkanHost {
            api_version: gpu_probe::VulkanVersion::new(1, 3, 0),
        });
        assert_eq!(
            select(&host, &e),
            Selection::Subprocess { index: 2 },
            "rocm must win over vulkan"
        );

        let e_no_rocm = entry(
            "subprocess",
            vec![sp("x86_64-unknown-linux-gnu", "cpu", None, None, false), vk],
        );
        assert_eq!(
            select(&host, &e_no_rocm),
            Selection::Subprocess { index: 1 },
            "vulkan must win over cpu"
        );
    }

    #[test]
    fn a_vulkan_asset_respects_its_api_floor() {
        let mut vk = sp("x86_64-unknown-linux-gnu", "cpu", None, None, false);
        vk.accel = vec!["vulkan".into()];
        vk.vulkan_api = Some("1.3".into());
        let e = entry(
            "subprocess",
            vec![sp("x86_64-unknown-linux-gnu", "cpu", None, None, false), vk],
        );
        let mut host = host_cpu();
        host.vulkan = Some(crate::registry::host::VulkanHost {
            api_version: gpu_probe::VulkanVersion::new(1, 2, 0),
        });
        assert_eq!(
            select(&host, &e),
            Selection::Subprocess { index: 0 },
            "a 1.2 host must not take a 1.3 build"
        );
    }

    /// A declared floor that does not parse must fail closed. `1.3.0` is the
    /// natural authoring mistake — `VulkanApi` carries no patch — and treating
    /// it as "no floor declared" would match every Vulkan host.
    #[test]
    fn a_malformed_vulkan_api_floor_fails_closed() {
        let mut vk = sp("x86_64-unknown-linux-gnu", "cpu", None, None, false);
        vk.accel = vec!["vulkan".into()];
        vk.vulkan_api = Some("1.3.0".into());
        let e = entry(
            "subprocess",
            vec![sp("x86_64-unknown-linux-gnu", "cpu", None, None, false), vk],
        );
        let mut host = host_cpu();
        // A host that would clear a well-formed `1.3`, so only the parse can
        // be what rejects the asset.
        host.vulkan = Some(crate::registry::host::VulkanHost {
            api_version: gpu_probe::VulkanVersion::new(1, 3, 0),
        });
        assert_eq!(
            select(&host, &e),
            Selection::Subprocess { index: 0 },
            "an unparseable floor must not be read as no floor at all"
        );
    }

    /// The reason must name the axis that *failed*. An sm_86 host told only
    /// `sm_86` learns nothing — its card is sm_86; the CUDA runtime major is
    /// what excluded the build — and it never learns what the builds wanted.
    #[test]
    fn the_incompatible_reason_names_the_runtime_and_what_the_builds_need() {
        let e = entry(
            "subprocess",
            vec![sp(
                "x86_64-unknown-linux-gnu",
                "cuda",
                Some(86),
                Some(13),
                false,
            )],
        );
        let Selection::Incompatible { reason } = select(&host_cuda(86, 12, false), &e) else {
            panic!("a cuda_major 13 build must not match a CUDA 12 host");
        };
        assert!(reason.contains("sm_86"), "{reason}");
        assert!(
            reason.contains("CUDA 12"),
            "the host's runtime major is the axis that failed: {reason}"
        );
        assert!(
            reason.contains("cuda 13"),
            "the reason must say what the candidate needed: {reason}"
        );
    }

    /// A ROCm host that matched nothing is told its targets and that the
    /// userspace version never gated the decision, pre-empting the "did you
    /// install ROCm?" red herring.
    #[test]
    fn the_incompatible_reason_names_gfx_targets_and_the_rocm_red_herring() {
        let e = entry(
            "subprocess",
            vec![sp_rocm("x86_64-unknown-linux-gnu", &["gfx1100"])],
        );
        let Selection::Incompatible { reason } = select(&host_rocm(&[(10, 3, 0)]), &e) else {
            panic!("a gfx1100 build must not match a gfx1030 host");
        };
        assert!(reason.contains("gfx1030"), "{reason}");
        assert!(reason.contains("no ROCm userspace found"), "{reason}");
        assert!(reason.contains("rocm gfx1100"), "{reason}");
    }

    #[test]
    fn target_mismatch_is_incompatible() {
        let e = entry(
            "subprocess",
            vec![sp("aarch64-unknown-linux-gnu", "cpu", None, None, false)],
        );
        let sel = select(&host_cuda(86, 12, false), &e);
        assert!(matches!(sel, Selection::Incompatible { .. }));
    }

    /// Every generation this build knows selects normally; the gate is only
    /// for the ones it does not.
    #[test]
    fn every_known_contract_selects() {
        for c in Contract::ALL {
            let mut e = entry("wasm", vec![]);
            e.assets.wasm = Some(IndexAsset {
                url: "https://x".into(),
                size: 1,
                sha256: "abc".into(),
            });
            e.contract = c.to_string();
            assert_eq!(select(&host_cpu(), &e), Selection::Wasm, "{c}");
        }
    }

    /// A generation this build does not know is incompatible before any asset
    /// question — even a perfectly good wasm asset cannot help — and the
    /// reason names the release to update to when the index stamped one.
    #[test]
    fn an_unknown_contract_is_incompatible_and_names_the_floor() {
        let mut e = entry("wasm", vec![]);
        e.assets.wasm = Some(IndexAsset {
            url: "https://x".into(),
            size: 1,
            sha256: "abc".into(),
        });
        e.contract = "v99".into();
        e.min_client = Some("9.9.9".into());
        let sel = select(&host_cpu(), &e);
        assert!(sel.needs_client_update(), "the remedy is a daemon update");
        let reason = sel
            .reason()
            .expect("a blocked entry states why")
            .to_string();
        assert!(reason.contains("9.9.9"), "{reason}");
        assert!(reason.contains("v99"), "{reason}");
        assert!(reason.contains(DAEMON.version), "{reason}");

        // An index published before the stamp still refuses, just without the
        // number.
        e.min_client = None;
        let reason = select(&host_cpu(), &e)
            .reason()
            .expect("still blocked without a stamp")
            .to_string();
        assert!(reason.contains("newer Super Test"), "{reason}");
        // The product is the daemon's, not a fixed one.
        let other = Daemon {
            product: &super_engine_protocol::test_product::OTHER,
            ..DAEMON
        };
        let reason = super::select::<TestProduct>(&other, &host_cpu(), &e)
            .reason()
            .expect("still blocked")
            .to_string();
        assert!(reason.contains("newer Super Other"), "{reason}");
    }

    /// A Mac offered both a Metal and a CPU build of the same backend must
    /// get the Metal one. Metal outranks the CPU for the same reason CUDA
    /// and ROCm do — it is the vendor's own path to the GPU — and without an
    /// arm in `score` it scores `None`, leaving every Mac on the CPU build
    /// with nothing in the logs to say why.
    #[test]
    fn a_mac_prefers_the_metal_asset_over_the_cpu_one() {
        let e = entry(
            "subprocess",
            vec![
                sp("aarch64-apple-darwin", "cpu", None, None, false),
                sp("aarch64-apple-darwin", "metal", None, None, false),
            ],
        );
        assert_eq!(
            select(&host_metal(), &e),
            Selection::Subprocess { index: 1 }
        );
    }

    /// A Metal build on a host without Metal is not installable, and the
    /// CPU build beside it is what the host gets instead.
    #[test]
    fn a_host_without_metal_falls_back_to_the_cpu_asset() {
        let e = entry(
            "subprocess",
            vec![
                sp("x86_64-unknown-linux-gnu", "metal", None, None, false),
                sp("x86_64-unknown-linux-gnu", "cpu", None, None, false),
            ],
        );
        assert_eq!(select(&host_cpu(), &e), Selection::Subprocess { index: 1 });
    }

    /// With only a Metal asset published and no Metal on the host, the entry
    /// is incompatible — and the reason names the target, since a Linux host
    /// reaching a darwin-only backend is the likely way to get here.
    #[test]
    fn a_metal_only_backend_is_incompatible_without_metal() {
        let e = entry(
            "subprocess",
            vec![sp("aarch64-apple-darwin", "metal", None, None, false)],
        );
        let sel = select(&host_cpu(), &e);
        let reason = sel.reason().expect("incompatible entries carry a reason");
        assert!(
            reason.contains("no asset for target"),
            "unexpected reason: {reason}"
        );
    }

    /// The incompatibility message has to say the host *has* Metal, or a
    /// backend author debugging why their darwin asset was refused is told
    /// only "cpu only" about a machine with a GPU.
    #[test]
    fn the_reason_reports_metal_among_the_hosts_capabilities() {
        let e = entry(
            "subprocess",
            vec![sp("aarch64-apple-darwin", "rocm", None, None, false)],
        );
        let sel = select(&host_metal(), &e);
        let reason = sel.reason().expect("incompatible entries carry a reason");
        assert!(reason.contains("metal"), "unexpected reason: {reason}");
        assert!(
            !reason.contains("cpu only"),
            "a Metal host is not cpu only: {reason}"
        );
    }

    // ---------- [[models.files]] variants ----------

    fn model(files: &str) -> ModelEntry<test_product::Model> {
        let text = format!(
            r#"
            [backend]
            source = "github.com/x/y"
            name = "Y"
            version = "1.0.0"
            kind = "subprocess"
            entrypoint = "y"
            contract = "v1"
            description = "Test backend."

            [[models]]
            name = "m"
            primary_language = "en"
            supported_languages = ["en"]
            supported_devices = ["cpu", "gpu"]
            files = [{files}]
            "#
        );
        super_engine_spec::manifest::Manifest::<TestProduct>::parse(&text)
            .expect("the fixture manifest parses")
            .models
            .into_iter()
            .next()
            .expect("one model")
    }

    fn urls<'a>(chosen: &[&'a FileSpec]) -> Vec<&'a str> {
        chosen.iter().map(|f| f.url.as_str()).collect()
    }

    /// One variant may cover several compute capabilities, which is what a
    /// pre-warmed kernel cache holding more than one device's entries is. It
    /// still loses to a variant naming this host alone only by declaration
    /// order, since both matched the host exactly.
    #[test]
    fn a_cuda_variant_may_cover_several_compute_capabilities() {
        let m = model(
            r#"
            { url = "https://h/ada", destination = "c/k", accel = "cuda", cuda_sm = [86, 89] },
            { url = "https://h/any", destination = "c/k", accel = "cuda" },
            "#,
        );
        for sm in [86, 89] {
            let chosen = select_files(&host_cuda(sm, 13, false), &m).expect("the list covers it");
            assert_eq!(urls(&chosen), vec!["https://h/ada"], "sm_{sm}");
        }
        // A capability the list does not name falls to the wildcard behind it.
        let chosen = select_files(&host_cuda(90, 13, false), &m).expect("the wildcard catches it");
        assert_eq!(urls(&chosen), vec!["https://h/any"]);
    }

    /// Every v1 manifest is a manifest of unconditional entries, and selection
    /// must be invisible to it: same files, same order, on any host.
    #[test]
    fn a_manifest_without_a_selector_yields_every_file_in_order() {
        let m = model(
            r#"
            { url = "https://h/a", destination = "m/a" },
            { url = "https://h/b", destination = "m/b" },
            "#,
        );
        for host in [
            host_cpu(),
            host_cuda(90, 13, true),
            host_rocm(&[(11, 0, 0)]),
        ] {
            let chosen = select_files(&host, &m).expect("unconditional files always resolve");
            assert_eq!(urls(&chosen), vec!["https://h/a", "https://h/b"]);
        }
    }

    /// The wildcard/exact preference `cuda_sm` was designed for, applied to a
    /// file: an sm-exact variant wins where it fits, and the wildcard behind it
    /// catches every other CUDA host. Exactly one file per destination either
    /// way — the point of grouping.
    #[test]
    fn an_exact_compute_capability_beats_a_wildcard_cuda_variant() {
        let m = model(
            r#"
            { url = "https://h/sm90", destination = "c/k", accel = "cuda", cuda_sm = 90 },
            { url = "https://h/any", destination = "c/k", accel = "cuda" },
            "#,
        );
        let chosen = select_files(&host_cuda(90, 13, false), &m).expect("the exact variant fits");
        assert_eq!(urls(&chosen), vec!["https://h/sm90"]);

        let chosen = select_files(&host_cuda(86, 13, false), &m).expect("the wildcard catches it");
        assert_eq!(urls(&chosen), vec!["https://h/any"]);
    }

    /// A pre-warmed kernel cache is not load-bearing: an unlisted GPU should
    /// load anyway and rebuild what it needs.
    #[test]
    fn an_optional_destination_with_no_match_is_skipped() {
        let m = model(
            r#"
            { url = "https://h/kernels", destination = "c/k", accel = "cuda", optional = true },
            { url = "https://h/weights", destination = "m/w" },
            "#,
        );
        let chosen = select_files(&host_cpu(), &m).expect("an optional hole is not an error");
        assert_eq!(urls(&chosen), vec!["https://h/weights"]);
    }

    /// An entry with no selector is the fallback, not a peer: a sibling that
    /// named this host outranks it, and it still catches everyone else.
    #[test]
    fn an_unconditional_entry_loses_to_a_variant_that_named_the_host() {
        let m = model(
            r#"
            { url = "https://h/generic", destination = "c/k" },
            { url = "https://h/cuda", destination = "c/k", accel = "cuda" },
            { url = "https://h/cpu", destination = "c/k", accel = "cpu" },
            "#,
        );
        let chosen = select_files(&host_cuda(86, 13, false), &m).expect("the cuda variant fits");
        assert_eq!(urls(&chosen), vec!["https://h/cuda"]);

        // No CUDA here, so the explicit `cpu` variant takes it — still ahead of
        // the entry that asked for nothing.
        let chosen = select_files(&host_cpu(), &m).expect("the cpu variant fits");
        assert_eq!(urls(&chosen), vec!["https://h/cpu"]);
    }

    /// Weights are load-bearing, so a hole is a refusal — and the refusal has
    /// to be actionable, which means naming both halves: what this machine is,
    /// and what the variants asked for.
    #[test]
    fn a_required_destination_with_no_match_names_the_host_and_the_variants() {
        let m = model(
            r#"
            { url = "https://h/cuda", destination = "m/w", accel = "cuda", cuda_sm = 90 },
            "#,
        );
        let reason = select_files(&host_cpu(), &m)
            .expect_err("a required CUDA file cannot resolve on a CPU-only host");
        assert!(reason.contains("m/w"), "{reason}");
        assert!(reason.contains("cpu only"), "{reason}");
        assert!(reason.contains("cuda"), "{reason}");
    }

    /// A file may say "any AMD host" where a build may not, because a build has
    /// to be ISA for one architecture and a file does not.
    #[test]
    fn a_rocm_variant_may_name_no_target_and_still_lose_to_one_that_does() {
        let m = model(
            r#"
            { url = "https://h/any-amd", destination = "c/k", accel = "rocm" },
            { url = "https://h/gfx1100", destination = "c/k", accel = "rocm", gfx = ["gfx1100"] },
            "#,
        );
        let chosen = select_files(&host_rocm(&[(11, 0, 0)]), &m).expect("both fit");
        assert_eq!(urls(&chosen), vec!["https://h/gfx1100"]);

        // A card neither variant names exactly still gets the wildcard.
        let chosen = select_files(&host_rocm(&[(9, 0, 10)]), &m).expect("the wildcard fits");
        assert_eq!(urls(&chosen), vec!["https://h/any-amd"]);
    }

    /// Declaration order is the author's preference order, so a tie goes to the
    /// first — the same tiebreak `select` applies to builds.
    #[test]
    fn a_tie_between_variants_goes_to_the_first_declared() {
        let m = model(
            r#"
            { url = "https://h/first", destination = "c/k", accel = "cuda" },
            { url = "https://h/second", destination = "c/k", accel = "cuda" },
            "#,
        );
        let chosen = select_files(&host_cuda(86, 13, false), &m).expect("both fit");
        assert_eq!(urls(&chosen), vec!["https://h/first"]);
    }
}
