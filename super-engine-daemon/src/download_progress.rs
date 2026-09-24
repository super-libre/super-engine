// SPDX-License-Identifier: GPL-3.0-only
//! What a model load reports while it provisions the model's files, and the
//! loads a daemon has in flight.
//!
//! A [`DownloadProgressTracker`] follows one load through its phases and
//! publishes each change on the `download_progress` topic; a
//! [`DownloadStateManager`] holds the loads in flight so a client can ask
//! after one, or cancel it.
//!
//! Which load a tracker is for is the product's to say, through its
//! [`Slot`]: a product that provisions each pipeline stage independently
//! keys a load by its stage and reports the stage and backend with every
//! tick; a product with one load at a time uses `()` and reports nothing
//! more.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use chrono::Utc;
use log::{info, warn};
use parking_lot::RwLock;
use serde::Serialize;
use super_engine_protocol::models::load_progress::LoadProgress;

use crate::events::CoreEvents;

/// Which load a tracker is for, as the product tells its loads apart and
/// reports them.
///
/// Serialized into every `download_progress` payload beside the shared keys,
/// so its fields are wire keys, such as a pipeline product's `source` and
/// `stage`.
pub trait Slot: Clone + Serialize + Send + Sync + 'static {
    /// What the [`DownloadStateManager`] keeps one load per.
    type Key: Copy + Eq + Hash + Send + Sync + 'static;

    /// This slot's key.
    fn key(&self) -> Self::Key;

    /// The key as the manager's refusals name it (`"stage 2"`), or `None`
    /// when the product has one load at a time and there is nothing to name.
    fn describe(key: Self::Key) -> Option<String>;
}

/// One load at a time, reporting nothing beyond the shared keys.
impl Slot for () {
    type Key = ();

    fn key(&self) {}

    fn describe((): ()) -> Option<String> {
        None
    }
}

/// The phases a load walks, in order. A product's client matches on these
/// strings, so they are wire values.
pub mod status {
    /// Checking the files already on disk. Every load starts here, and a
    /// fully cached one never leaves it.
    pub const VERIFYING: &str = "verifying";
    /// Bytes coming off the network.
    pub const DOWNLOADING: &str = "downloading";
    /// Files all present; the backend is loading the model. The payload's
    /// `load` says what the backend reports of it, when it reports anything.
    pub const LOADING_MODEL: &str = "loading_model";
    /// Terminal: the model is loaded.
    pub const COMPLETED: &str = "completed";
    /// Terminal: the user cancelled.
    pub const CANCELLED: &str = "cancelled";
    /// Terminal: the load failed; the payload's `error` says why.
    pub const ERROR: &str = "error";
}

/// A snapshot of one load, with the keys the `download_progress` payload
/// carries: the product's [`Slot`] keys flattened in beside the shared ones.
#[derive(Clone, Debug, Serialize)]
pub struct Progress<S> {
    pub model_name: String,
    #[serde(flatten)]
    pub slot: S,
    pub current_file: String,
    pub file_index: usize,
    pub total_files: usize,
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
    pub percentage: f32,
    /// One of the [`status`] phases.
    pub status: String,
    pub started_at: String,
    pub eta_seconds: Option<u64>,
    /// Failure detail, present only when `status` is [`status::ERROR`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The backend's own account of the load, once `status` is
    /// [`status::LOADING_MODEL`] and the backend has said anything. See
    /// [`LoadProgress`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<LoadProgress>,
}

/// Progress of one model load: its files, the bytes of the current one, and
/// the phase it is in.
pub struct DownloadProgressTracker<S> {
    pub model_name: String,
    /// Which load this is. Reported on every tick so a client can put the
    /// progress where the load started: the model name alone does not say
    /// whose it is.
    pub slot: S,
    pub current_file: Arc<RwLock<String>>,
    pub file_index: AtomicUsize,
    pub total_files: AtomicUsize,
    /// Bytes of the current file accounted for so far: streamed off the
    /// network while downloading, read off disk while verifying.
    pub bytes_downloaded: AtomicU64,
    pub total_bytes: AtomicU64,
    /// Phase of the provisioning run, in the order a load walks them — see
    /// [`status`]. A fully cached model never reaches `downloading`, which is
    /// what lets a client say "checking files" instead of claiming a download
    /// that isn't happening.
    pub status: Arc<RwLock<String>>,
    /// Failure detail set by [`Self::mark_error`]; included in the
    /// `download_progress` payload so a client can show why a switch failed.
    pub error: Arc<RwLock<Option<String>>>,
    /// What the backend last reported of its load. Set by
    /// [`Self::set_load_progress`].
    pub load: Arc<RwLock<Option<LoadProgress>>>,
    pub started_at: Instant,
    pub started_at_str: String,
    pub cancelled: Arc<AtomicBool>,
    /// Optional event bus the tracker publishes `download_progress` events
    /// into. Set via [`Self::with_event_bus`]; when `None` the `/events`
    /// channel sees nothing.
    pub events: Option<Arc<dyn CoreEvents>>,
    /// The percentage most recently broadcast, as fixed point (percentage *
    /// 100).
    last_broadcast_percentage: AtomicU64,
    /// The `status` string we most recently broadcast. Used so that
    /// transitions to "completed" / "cancelled" / "error" are emitted
    /// even when the 1%-increment percentage gate would otherwise
    /// suppress them.
    last_broadcast_status: Arc<RwLock<String>>,
    /// The `total_bytes` value we most recently broadcast. A change
    /// here (typically 0 → file size, once we resolve it from
    /// `X-Linked-Size` / `Content-Length` / HEAD) must publish even
    /// when neither percentage nor status changed — otherwise the UI's
    /// "x.x / y.y MB" line stays at "0.0 / 0.0 MB" until enough bytes
    /// stream for the percentage to cross a 1% boundary, which for a
    /// multi-GB file can be several seconds of frozen UI.
    last_broadcast_total_bytes: AtomicU64,
    /// The `file_index` we most recently broadcast. File transitions
    /// (per-file `total_bytes`/`bytes_downloaded` reset, percentage
    /// dropping from ~90% back to 0%) must publish even when the new
    /// file happens to be the same size as the previous one — the
    /// percentage drop alone is *not* caught by `percentage_crossed`
    /// (which only fires on increases). Initialized to `usize::MAX`
    /// so the very first broadcast also fires.
    last_broadcast_file_index: AtomicUsize,
    /// The `load` we most recently broadcast. A backend's report changes while
    /// the percentage above sits at 100, so it is gated on its own.
    last_broadcast_load: RwLock<Option<LoadProgress>>,
}

impl<S: Slot> DownloadProgressTracker<S> {
    #[must_use]
    pub fn new(
        model_name: String,
        slot: S,
        total_files: usize,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            model_name,
            slot,
            current_file: Arc::new(RwLock::new(String::new())),
            file_index: AtomicUsize::new(0),
            total_files: AtomicUsize::new(total_files),
            bytes_downloaded: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            // Provisioning opens by checking the files already on disk, not by
            // downloading — a tracker that announced "downloading" before the
            // first `usable_existing` call is what made a fully cached load
            // paint a download bar.
            status: Arc::new(RwLock::new(status::VERIFYING.to_string())),
            error: Arc::new(RwLock::new(None)),
            load: Arc::new(RwLock::new(None)),
            started_at: Instant::now(),
            started_at_str: Utc::now().to_rfc3339(),
            cancelled,
            events: None,
            last_broadcast_percentage: AtomicU64::new(0),
            last_broadcast_status: Arc::new(RwLock::new(String::new())),
            last_broadcast_total_bytes: AtomicU64::new(0),
            last_broadcast_file_index: AtomicUsize::new(usize::MAX),
            last_broadcast_load: RwLock::new(None),
        }
    }

    /// Attach the daemon's event bus so progress updates fan out as
    /// `download_progress` events on `GET /events`.
    #[must_use]
    pub fn with_event_bus<E: CoreEvents + 'static>(mut self, events: Arc<E>) -> Self {
        self.events = Some(events);
        self
    }

    /// Where the load is now.
    #[must_use]
    pub fn get_progress(&self) -> Progress<S> {
        let bytes_downloaded = self.bytes_downloaded.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);

        let status = self.status.read().clone();
        let percentage: f32 = if status == status::COMPLETED || status == status::LOADING_MODEL {
            // Files are all on disk. The remaining work (spawning the
            // backend, loading weights onto the device) isn't
            // byte-tracked, so keep the bar full — the app shows a
            // separate "Loading…" indicator for the `loading_model`
            // phase.
            100.0
        } else if total_bytes > 0 {
            // Per-file progress: how much of the *current* file has
            // arrived (or, in the `verifying` phase, been hashed off
            // disk), matching the per-file "X.X / Y.Y MB" readout.
            // `bytes_downloaded`/`total_bytes` reset at each file
            // boundary (`start_file`), so the bar fills 0→100% per file
            // and the last file's final chunk fills it to the end. The
            // `file_index` counter ("2/4") conveys which file is in
            // flight.
            percent_of(bytes_downloaded, total_bytes)
        } else {
            // Size for the current file not resolved yet (or there's
            // nothing to download).
            0.0
        };

        let elapsed = self.started_at.elapsed().as_secs();
        let eta_seconds = if bytes_downloaded > 0 && total_bytes > bytes_downloaded {
            let remaining_bytes = total_bytes - bytes_downloaded;
            let bytes_per_second = bytes_downloaded / elapsed.max(1);
            remaining_bytes.checked_div(bytes_per_second)
        } else {
            None
        };

        Progress {
            model_name: self.model_name.clone(),
            slot: self.slot.clone(),
            current_file: self.current_file.read().clone(),
            file_index: self.file_index.load(Ordering::Relaxed),
            total_files: self.total_files.load(Ordering::Relaxed),
            bytes_downloaded,
            total_bytes,
            percentage,
            status,
            started_at: self.started_at_str.clone(),
            eta_seconds,
            error: self.error.read().clone(),
            load: self.load.read().clone(),
        }
    }

    /// Broadcast a progress update on the `/events` bus. Throttled to 1%
    /// increments so a tight streaming download doesn't flood
    /// subscribers — but any transition to a terminal `status` value
    /// (`completed` / `cancelled` / `error`) always publishes, since
    /// the consumer's `if progress.status == "completed"` arm clears
    /// the in-UI download indicator and a dropped event there leaves
    /// the UI permanently stuck.
    pub fn broadcast_progress(&self) {
        let progress = self.get_progress();

        // Clamp, round and convert to a fixed-point integer (percentage * 100)
        let current_percentage = fixed_point(progress.percentage);
        let last_percentage = self.last_broadcast_percentage.load(Ordering::Relaxed);

        let status_changed = {
            let last = self.last_broadcast_status.read().clone();
            last != progress.status
        };
        let percentage_crossed =
            current_percentage > last_percentage && current_percentage - last_percentage >= 100;
        // Newly-resolved file size — broadcast immediately so the UI's
        // "x.x / y.y MB" line flips from "0.0 / 0.0 MB" to the real total
        // before the first chunk's percentage update lands.
        let total_bytes_changed =
            self.last_broadcast_total_bytes.load(Ordering::Relaxed) != progress.total_bytes;
        // File boundary — per-file counters reset at the start of the
        // next file, so we publish even if the new file's size matches
        // the previous file's (which would otherwise leave every
        // throttle arm unchanged).
        let file_index_changed =
            self.last_broadcast_file_index.load(Ordering::Relaxed) != progress.file_index;
        let load_changed = load_moved(
            self.last_broadcast_load.read().as_ref(),
            progress.load.as_ref(),
        );

        if status_changed
            || percentage_crossed
            || total_bytes_changed
            || file_index_changed
            || load_changed
        {
            self.last_broadcast_percentage
                .store(current_percentage, Ordering::Relaxed);
            self.last_broadcast_status
                .write()
                .clone_from(&progress.status);
            self.last_broadcast_total_bytes
                .store(progress.total_bytes, Ordering::Relaxed);
            self.last_broadcast_file_index
                .store(progress.file_index, Ordering::Relaxed);
            self.last_broadcast_load.write().clone_from(&progress.load);

            if let Some(ref events) = self.events {
                let mut payload =
                    serde_json::to_value(&progress).unwrap_or_else(|_| serde_json::json!({}));
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert(
                        "timestamp".to_string(),
                        serde_json::Value::String(Utc::now().to_rfc3339()),
                    );
                }
                events.publish_download_progress(payload);
            }
        }
    }

    /// Advance the tracker to the next file. Purely a state update — the
    /// caller logs, because only it knows whether the file is being fetched
    /// or was already on disk (cached files come through here too, so the
    /// progress bar advances without claiming a download happened).
    pub fn start_file(&self, filename: &str, file_index: usize) {
        *self.current_file.write() = filename.to_string();
        self.file_index.store(file_index, Ordering::Relaxed);
        // Per-file counters: `total_bytes` and `bytes_downloaded`
        // reflect only the current file, so each file's UI display
        // is "X.X / <this file's size> MB" rather than an aggregate
        // across the whole model (which is confusing when sizes
        // vary by orders of magnitude — `config.json` is sub-MB,
        // `model-*.safetensors` is multi-GB). The caller publishes
        // the new file's real numbers after this returns: cached
        // files store `(md.len(), md.len())` directly, fresh
        // downloads resolve size via `X-Linked-Size`/HEAD and store
        // `(file_size, 0)`. Until then we're at 0/0, but no
        // broadcast goes out between this reset and the caller's
        // store, so the UI never observes the transient.
        self.bytes_downloaded.store(0, Ordering::Relaxed);
        self.total_bytes.store(0, Ordering::Relaxed);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
        *self.status.write() = status::CANCELLED.to_string();
        warn!("Download cancelled for model: {}", self.model_name);
    }

    /// Enter the `verifying` phase: the file named by the last
    /// [`Self::start_file`] is on disk and is being checked (size, and its
    /// declared SHA-256) rather than fetched. `bytes_downloaded` tracks the
    /// bytes hashed so far, so the client's bar moves through a multi-GB
    /// checksum instead of sitting frozen on the previous file's numbers.
    ///
    /// Every file starts here, and a fully cached model never leaves it — that
    /// is what keeps a cached load from claiming to download anything.
    pub fn mark_verifying(&self) {
        *self.status.write() = status::VERIFYING.to_string();
    }

    /// Enter the `downloading` phase: the file named by the last
    /// [`Self::start_file`] is absent (or failed verification) and bytes are
    /// about to come off the network.
    pub fn mark_downloading(&self) {
        *self.status.write() = status::DOWNLOADING.to_string();
    }

    /// Mark the file-download phase done and the (untracked) weight-load
    /// phase begun. A settings app maps this status to a "Loading model
    /// into memory…" indicator, so the user sees the operation is still
    /// progressing after the download bar fills.
    pub fn mark_loading(&self) {
        *self.status.write() = status::LOADING_MODEL.to_string();
        info!(
            "Files downloaded; loading model into memory: {}",
            self.model_name
        );
    }

    /// Record what the backend reports of its load, replacing what it
    /// reported before. The caller broadcasts.
    pub fn set_load_progress(&self, load: LoadProgress) {
        *self.load.write() = Some(load);
    }

    pub fn mark_completed(&self) {
        *self.status.write() = status::COMPLETED.to_string();
        info!("Download completed for model: {}", self.model_name);
    }

    pub fn mark_error(&self, error: &str) {
        *self.status.write() = status::ERROR.to_string();
        *self.error.write() = Some(error.to_string());
        warn!("Download error for model {}: {}", self.model_name, error);
    }
}

/// Whether a backend's load report has changed enough to publish: a new phase
/// or step, progress appearing or going away, or progress moving by a
/// percentage point. Finer movement waits for the next point, as the download
/// bar's does.
fn load_moved(last: Option<&LoadProgress>, now: Option<&LoadProgress>) -> bool {
    match (last, now) {
        (None, None) => false,
        (Some(last), Some(now)) => {
            last.phase != now.phase
                || last.step != now.step
                || match (last.progress, now.progress) {
                    (Some(a), Some(b)) => (a - b).abs() >= 0.01,
                    (a, b) => a.is_some() != b.is_some(),
                }
        }
        _ => true,
    }
}

/// `part` as a percentage of a non-zero `whole`, capped at 100. Byte counts
/// are far below the range where the float conversion loses anything a
/// progress bar could show.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn percent_of(part: u64, whole: u64) -> f32 {
    ((part as f64 / whole as f64) * 100.0).min(100.0) as f32
}

/// A percentage as fixed point (percentage * 100), clamped to 0–100 first.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn fixed_point(percentage: f32) -> u64 {
    (percentage.clamp(0.0, 100.0) * 100.0).round() as u64
}

/// The loads a daemon has in flight, one per [`Slot::Key`].
///
/// A pipeline's stages provision independently — the second stage's model
/// can be fetched while the first's is — and nothing serializes the two, so a single slot meant whichever load started second evicted the
/// other: its progress vanished from the stage reporting it, and its cancel
/// had nothing left to cancel. Keyed by slot, each answers only for itself.
pub struct DownloadStateManager<S: Slot> {
    downloads: RwLock<HashMap<S::Key, Arc<DownloadProgressTracker<S>>>>,
}

impl<S: Slot> Default for DownloadStateManager<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Slot> DownloadStateManager<S> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            downloads: RwLock::new(HashMap::new()),
        }
    }

    /// Start tracking a load in the slot the tracker names.
    ///
    /// # Errors
    ///
    /// Returns an error if that slot already has a load in progress.
    pub fn start_download(&self, tracker: Arc<DownloadProgressTracker<S>>) -> Result<(), String> {
        let mut downloads = self.downloads.write();
        let key = tracker.slot.key();
        if downloads.contains_key(&key) {
            return Err(format!(
                "A download is already in progress{}",
                naming::<S>(key)
            ));
        }
        downloads.insert(key, tracker);
        Ok(())
    }

    /// The load `key` has in flight, if any.
    #[must_use]
    pub fn get_download(&self, key: S::Key) -> Option<Arc<DownloadProgressTracker<S>>> {
        self.downloads.read().get(&key).cloned()
    }

    /// Cancel the load `key` has in flight.
    ///
    /// # Errors
    ///
    /// Returns an error when that slot has nothing to cancel — including when
    /// another slot is loading, which is not this slot's to abandon.
    pub fn cancel_download(&self, key: S::Key) -> Result<(), String> {
        match self.downloads.read().get(&key) {
            Some(tracker) => {
                tracker.cancel();
                Ok(())
            }
            None => Err(format!("No download in progress{}", naming::<S>(key))),
        }
    }

    /// Forget `key`'s load, whatever became of it.
    pub fn clear_download(&self, key: S::Key) {
        self.downloads.write().remove(&key);
    }
}

/// `" for stage 2"`, or nothing for a product with one slot.
fn naming<S: Slot>(key: S::Key) -> String {
    S::describe(key).map_or_else(String::new, |d| format!(" for {d}"))
}

#[cfg(test)]
#[path = "download_progress_tests.rs"]
mod tests;
