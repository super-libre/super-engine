// SPDX-License-Identifier: GPL-3.0-only
use super::*;

/// A product that provisions per pipeline stage, as Super STT does.
#[derive(Clone, Debug, Serialize)]
struct Stage {
    source: String,
    stage: u32,
}

impl Slot for Stage {
    type Key = u32;

    fn key(&self) -> u32 {
        self.stage
    }

    fn describe(key: u32) -> Option<String> {
        Some(format!("stage {key}"))
    }
}

/// A single-slot tracker for `model`, the shape most tests here use.
fn tracker(model: &str, total_files: usize) -> DownloadProgressTracker<()> {
    DownloadProgressTracker::new(
        model.to_string(),
        (),
        total_files,
        Arc::new(AtomicBool::new(false)),
    )
}

fn stage_tracker(model: &str, stage: u32) -> DownloadProgressTracker<Stage> {
    DownloadProgressTracker::new(
        model.to_string(),
        Stage {
            source: "github.com/x/y".to_string(),
            stage,
        },
        1,
        Arc::new(AtomicBool::new(false)),
    )
}

fn staged(model: &str, stage: u32) -> Arc<DownloadProgressTracker<Stage>> {
    Arc::new(stage_tracker(model, stage))
}

// A bus with the core topics only.
crate::event_topics! {}

/// Regression for the silent UI-stuck bug: when the post-download
/// `mark_completed()` runs and `broadcast_progress()` is called,
/// the underlying computed percentage often isn't strictly greater
/// than the last broadcast (it may even drop). The 1%-increment
/// throttle alone would suppress the publish, and the consumer's
/// `if progress.status == "completed"` arm would never fire — the
/// "downloading" indicator would stay forever. Status transitions
/// must bypass the throttle.
#[test]
fn broadcast_progress_publishes_completed_status_even_without_percentage_increase() {
    let tracker = tracker("test-model", 1);
    tracker.total_bytes.store(1000, Ordering::Relaxed);
    tracker.bytes_downloaded.store(900, Ordering::Relaxed);

    // Simulate the throttle having already seen 90%.
    tracker
        .last_broadcast_percentage
        .store(9000, Ordering::Relaxed);
    *tracker.last_broadcast_status.write() = "downloading".to_string();

    // Now mark completed without bumping bytes_downloaded — so the
    // computed percentage stays at 90 — and confirm the broadcast
    // path still fired, evidenced by `last_broadcast_status`.
    *tracker.status.write() = "completed".to_string();
    tracker.broadcast_progress();

    assert_eq!(
        *tracker.last_broadcast_status.read(),
        "completed",
        "broadcast must fire on status transition to `completed` regardless of percentage"
    );
}

/// Regression for the "0.0 / 0.0 MB" UI bug: when a download starts
/// with `total_bytes = 0` (a CDN serving large files chunked, with no
/// `Content-Length`), the first broadcast publishes `total_bytes = 0`.
/// Once the daemon resolves the real size via `X-Linked-Size`/HEAD, it
/// bumps `total_bytes` and calls `broadcast_progress()` — but
/// `bytes_downloaded` is still 0, so percentage stays 0% and status stays
/// "downloading". Without detecting the `total_bytes` change, the throttle
/// would suppress the publish and the UI would freeze on "0.0 / 0.0 MB"
/// until enough chunks streamed to cross the 1% gate.
#[test]
fn broadcast_progress_publishes_when_total_bytes_changes() {
    let tracker = tracker("test-model", 1);

    // Initial broadcast — empty last status → "verifying", total_bytes = 0.
    tracker.broadcast_progress();
    assert_eq!(
        tracker.last_broadcast_total_bytes.load(Ordering::Relaxed),
        0
    );

    // Size resolves (4 GB). bytes_downloaded still 0, status
    // unchanged, percentage still 0%. The publish must fire because
    // total_bytes changed.
    tracker.total_bytes.store(4_000_000_000, Ordering::Relaxed);
    tracker.broadcast_progress();
    assert_eq!(
        tracker.last_broadcast_total_bytes.load(Ordering::Relaxed),
        4_000_000_000,
        "broadcast must fire when total_bytes flips from 0 to the resolved file size"
    );
}

/// Per-file counters: `start_file` zeroes `total_bytes` and
/// `bytes_downloaded` so the UI's "X.X / Y.Y MB" displays only
/// the current file's size, not an aggregate across the whole
/// model. Without this, a multi-file model (two 3GB safetensors plus a
/// config) shows a cumulative "1500 / 6000 MB" mid-second-file, which is
/// confusing.
#[test]
fn start_file_resets_per_file_counters() {
    let tracker = tracker("test-model", 2);

    // Simulate file 0 finishing.
    tracker.total_bytes.store(3_000_000_000, Ordering::Relaxed);
    tracker
        .bytes_downloaded
        .store(3_000_000_000, Ordering::Relaxed);

    // Starting file 1 must zero out per-file counters so the next
    // size resolution / chunk doesn't accumulate on top of file 0.
    tracker.start_file("model-00002-of-00002.safetensors", 1);
    assert_eq!(tracker.total_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(tracker.bytes_downloaded.load(Ordering::Relaxed), 0);
    assert_eq!(tracker.file_index.load(Ordering::Relaxed), 1);
}

/// File-index transitions must publish even when the percentage is flat
/// across the boundary: file N finishing and file N+1 starting at the same
/// size leave neither `percentage_crossed` nor `total_bytes_changed` firing,
/// so without the `file_index` arm the throttle would suppress the publish
/// and the per-file "X / Y MB" display would stay frozen on the old file.
#[test]
fn broadcast_progress_publishes_when_file_index_advances() {
    let tracker = tracker("test-model", 2);

    tracker.total_bytes.store(1000, Ordering::Relaxed);
    tracker.bytes_downloaded.store(1000, Ordering::Relaxed);
    tracker.broadcast_progress();
    assert_eq!(tracker.last_broadcast_file_index.load(Ordering::Relaxed), 0);

    // File 1 starts at 0 bytes, same size. Only file_index moved.
    tracker.start_file("file2", 1);
    tracker.total_bytes.store(1000, Ordering::Relaxed);
    tracker.broadcast_progress();
    assert_eq!(
        tracker.last_broadcast_file_index.load(Ordering::Relaxed),
        1,
        "file_index update must publish even when the percentage is flat across the boundary"
    );
}

/// The per-file bar reaches 100% when the current file is fully
/// downloaded — no 90% cap. (The last file hitting 100%, then
/// `loading_model`/`completed`, fills the bar to the end of the whole
/// operation.)
#[test]
fn percentage_reaches_100_when_current_file_complete() {
    let tracker = tracker("m", 3);
    tracker.start_file("f3", 2);
    tracker.total_bytes.store(500, Ordering::Relaxed);
    tracker.bytes_downloaded.store(500, Ordering::Relaxed);
    let pct = tracker.get_progress().percentage;
    assert!((pct - 100.0).abs() < 0.01, "expected 100%, got {pct}");
}

/// Per-file bar: progress is the current file's byte fraction, not
/// an aggregate across files. A half-downloaded second file reads
/// 50% regardless of how large the already-finished first file was.
#[test]
fn percentage_is_per_file_not_aggregate() {
    let tracker = tracker("m", 2);
    tracker.start_file("f2", 1);
    tracker.total_bytes.store(1000, Ordering::Relaxed);
    tracker.bytes_downloaded.store(500, Ordering::Relaxed);
    let pct = tracker.get_progress().percentage;
    assert!(
        (pct - 50.0).abs() < 0.01,
        "expected per-file 50%, got {pct}"
    );
}

/// `loading_model` and `completed` both pin the bar at 100% — the
/// post-download weight-load phase keeps the bar full while the app
/// shows its "Loading…" indicator.
#[test]
fn loading_and_completed_statuses_are_100_percent() {
    let tracker = tracker("m", 2);
    tracker.start_file("f1", 0);
    tracker.total_bytes.store(500, Ordering::Relaxed);
    tracker.bytes_downloaded.store(100, Ordering::Relaxed);

    tracker.mark_loading();
    assert!((tracker.get_progress().percentage - 100.0).abs() < 0.01);

    tracker.mark_completed();
    assert!((tracker.get_progress().percentage - 100.0).abs() < 0.01);
}

/// Provisioning opens in the `verifying` phase, not `downloading`: the
/// first thing a load does is check the files already on disk, and a
/// tracker that said "downloading" before that check is what made a fully
/// cached load paint a download bar with nothing downloading behind it.
#[test]
fn a_fresh_tracker_starts_in_the_verifying_phase() {
    let tracker = tracker("m", 3);
    assert_eq!(tracker.get_progress().status, status::VERIFYING);
}

/// The verify → download flip publishes even when nothing else moved: a
/// file that failed its existence check goes from `verifying` at 0 bytes
/// to `downloading` at 0 bytes, so only the status distinguishes them, and
/// a client that missed the transition would keep saying "checking files"
/// for the whole of a multi-GB download.
#[test]
fn broadcast_progress_publishes_the_verify_to_download_flip() {
    let tracker = tracker("m", 1);
    tracker.start_file("model.safetensors", 0);
    tracker.broadcast_progress();
    assert_eq!(*tracker.last_broadcast_status.read(), "verifying");

    tracker.mark_downloading();
    tracker.broadcast_progress();
    assert_eq!(
        *tracker.last_broadcast_status.read(),
        "downloading",
        "the phase flip must publish even with byte counters unchanged"
    );
}

/// Verification reports progress the same way a download does — bytes of
/// the current file over its size — so a client renders one bar for both
/// phases and only the verb changes.
#[test]
fn verifying_reports_per_file_byte_progress() {
    let tracker = tracker("m", 2);
    tracker.start_file("model.safetensors", 1);
    tracker.mark_verifying();
    tracker.total_bytes.store(4000, Ordering::Relaxed);
    tracker.bytes_downloaded.store(1000, Ordering::Relaxed);

    let progress = tracker.get_progress();
    assert_eq!(progress.status, "verifying");
    assert!(
        (progress.percentage - 25.0).abs() < 0.01,
        "expected a quarter of the file hashed, got {}",
        progress.percentage
    );
}

/// Companion of the tests above: when nothing meaningful changes
/// (percentage, status, `total_bytes`, `file_index` all stable), the
/// throttle suppresses the publish. Without this guard,
/// `broadcast_progress` would spam events on every chunk.
#[test]
fn broadcast_progress_suppressed_when_neither_percentage_nor_status_changes() {
    let tracker = tracker("test-model", 1);
    tracker.total_bytes.store(1000, Ordering::Relaxed);
    tracker.bytes_downloaded.store(500, Ordering::Relaxed);

    // First broadcast — the sole file at 500/1000 = 50%, fixed-point 5000.
    tracker.broadcast_progress();
    let after_first = tracker.last_broadcast_percentage.load(Ordering::Relaxed);
    assert_eq!(after_first, 5000);

    // Same percentage, same status, same file_index → no change.
    tracker.broadcast_progress();
    assert_eq!(
        tracker.last_broadcast_percentage.load(Ordering::Relaxed),
        5000,
        "second call with identical state must be a no-op"
    );
}

/// The slot's keys ride beside the shared ones, so a client can tell whose
/// load a tick is for; a single-slot product's payload carries none, and an
/// `error` key appears only on the tick that has one.
#[test]
fn the_payload_carries_the_slots_keys_and_an_error_only_when_there_is_one() {
    let staged = staged("s1-mini-q4_k_m", 2);
    let json = serde_json::to_value(staged.get_progress()).unwrap();
    assert_eq!(json["model_name"], "s1-mini-q4_k_m");
    assert_eq!(json["source"], "github.com/x/y");
    assert_eq!(json["stage"], 2);
    assert!(
        json.get("error").is_none(),
        "no error key on a healthy tick"
    );

    let single = tracker("kokoro", 1);
    single.mark_error("disk full");
    let json = serde_json::to_value(single.get_progress()).unwrap();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(!keys.contains(&"source") && !keys.contains(&"stage"));
    assert_eq!(json["status"], "error");
    assert_eq!(json["error"], "disk full");
}

/// A published tick is the snapshot's keys plus a `timestamp`.
#[tokio::test]
async fn a_broadcast_publishes_the_snapshot_on_the_bus() {
    let bus = Arc::new(EventBus::new());
    let mut rx = bus.subscribe(Topic::DownloadProgress);
    let tracker = stage_tracker("m", 1).with_event_bus(bus.clone());
    tracker.broadcast_progress();

    let (topic, payload) = rx.recv_json().await.expect("a tick");
    assert_eq!(topic, "download_progress");
    assert_eq!(payload["stage"], 1);
    assert_eq!(payload["status"], "verifying");
    assert!(payload["timestamp"].is_string());
}

/// The stages provision independently, so one slot per stage: a
/// post-processor's download must not evict the transcription model's —
/// which is what left the evicted one's progress unreportable and its
/// cancel with nothing to cancel.
#[test]
fn each_slot_tracks_its_own_download() {
    let manager = DownloadStateManager::new();
    let stage_one = staged("whisper-large-v3", 1);
    let stage_two = staged("s1-mini-q4_k_m", 2);

    manager
        .start_download(Arc::clone(&stage_one))
        .expect("stage 1");
    manager
        .start_download(Arc::clone(&stage_two))
        .expect("stage 2");

    assert_eq!(
        manager
            .get_download(1)
            .expect("stage 1 download")
            .model_name,
        "whisper-large-v3"
    );
    assert_eq!(
        manager
            .get_download(2)
            .expect("stage 2 download")
            .model_name,
        "s1-mini-q4_k_m"
    );

    // Cancelling one leaves the other running.
    manager.cancel_download(2).expect("cancel stage 2");
    assert!(stage_two.is_cancelled());
    assert!(!stage_one.is_cancelled());

    // And clearing one leaves the other tracked.
    manager.clear_download(2);
    assert!(manager.get_download(2).is_none());
    assert!(manager.get_download(1).is_some());
}

/// A slot with nothing of its own in flight has nothing to cancel, even
/// while another slot downloads: one stage's cancel is not a licence to
/// abandon the other's load.
#[test]
fn a_slot_cannot_cancel_another_slots_download() {
    let manager = DownloadStateManager::new();
    let stage_one = staged("whisper-tiny", 1);
    manager
        .start_download(Arc::clone(&stage_one))
        .expect("stage 1");

    let err = manager.cancel_download(2).expect_err("nothing in stage 2");
    assert_eq!(err, "No download in progress for stage 2");
    assert!(!stage_one.is_cancelled());
}

/// One slot cannot start two loads at once — the second would leave the
/// first untrackable and uncancellable.
#[test]
fn a_slot_takes_one_download_at_a_time() {
    let manager = DownloadStateManager::new();
    manager
        .start_download(staged("whisper-tiny", 1))
        .expect("first");
    let err = manager
        .start_download(staged("whisper-large-v3", 1))
        .expect_err("a second load in the same stage");
    assert_eq!(err, "A download is already in progress for stage 1");
}

/// A single-slot product has one load at a time, and its refusals name no
/// slot.
#[test]
fn a_single_slot_manager_holds_one_load() {
    let manager = DownloadStateManager::<()>::new();
    assert_eq!(
        manager.cancel_download(()).expect_err("nothing yet"),
        "No download in progress"
    );

    let first = Arc::new(tracker("kokoro", 1));
    manager.start_download(Arc::clone(&first)).expect("first");
    assert_eq!(
        manager
            .start_download(Arc::new(tracker("piper", 1)))
            .expect_err("a second load"),
        "A download is already in progress"
    );

    manager.cancel_download(()).expect("cancel");
    assert!(first.is_cancelled());
    assert_eq!(first.get_progress().status, status::CANCELLED);

    manager.clear_download(());
    assert!(manager.get_download(()).is_none());
}
