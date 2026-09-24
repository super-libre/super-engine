// SPDX-License-Identifier: GPL-3.0-only
//! What a backend says about its own load, as a daemon relays it.
//!
//! While its `GET /v1/status` reports `state: "loading"`, a backend may add
//! `phase`, `step` and `progress`: a first load that builds its GPU kernels,
//! the weights coming off disk, a warm-up pass. The daemon forwards them in
//! its load-progress event as a [`LoadProgress`], and a client words them.
//!
//! The ids are a fixed vocabulary, listed in [`phase`] and [`step`], so each
//! client maps them to its own text. An id a client does not know is still a
//! load in progress: it shows a generic line for it, never an error.

use serde::{Deserialize, Serialize};

/// The kinds of load a backend can be in. See [`LoadProgress::phase`].
pub mod phase {
    /// A first load, paying a cost later loads skip: building and tuning GPU
    /// kernels for this device, for instance. A client titles it as setup, so
    /// the user knows the wait is a one-off.
    pub const INITIAL_SETUP: &str = "initial_setup";
    /// An ordinary load.
    pub const LOADING: &str = "loading";
}

/// What a load can be doing. See [`LoadProgress::step`].
pub mod step {
    /// Reading the model's weights and placing them on the device.
    pub const LOADING_WEIGHTS: &str = "loading_weights";
    /// Compiling and tuning GPU kernels, which a backend caches after the
    /// first load.
    pub const BUILDING_KERNELS: &str = "building_kernels";
    /// Running the model once so the first real request is not the slow one.
    pub const WARMING_UP: &str = "warming_up";
}

/// A backend's own account of its load in progress.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoadProgress {
    /// The kind of load: `initial_setup` for a first load that pays a one-time
    /// cost, `loading` otherwise. Absent when the backend does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// What the load is doing now: `loading_weights`, `building_kernels` or
    /// `warming_up`, or an id from a newer backend, which a client shows as a
    /// load in progress. Absent when the backend does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// How far through `step` the load is, 0.0 to 1.0, or through the whole
    /// load when there is no `step`. Absent when the backend cannot tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<f32>,
}

/// Longest id accepted from a backend. The vocabulary's own ids are far
/// shorter; this only bounds what a misbehaving backend can put in front of a
/// user.
const MAX_ID_LEN: usize = 64;

impl LoadProgress {
    /// Read the load fields from a backend's `GET /v1/status` body, or `None`
    /// when it carries none of them.
    ///
    /// The values come from the backend, so each is checked before it is
    /// passed on. An id must look like one: lowercase letters, digits and
    /// underscores, at most 64 of them. That keeps prose and markup out of a
    /// client that would otherwise show it. A `progress` outside 0 to 1 is
    /// clamped to it, and one that is not a finite number is dropped. A field
    /// that fails its check is treated as absent, and the rest are kept.
    #[must_use]
    pub fn from_status(status: &serde_json::Value) -> Option<Self> {
        let id = |key: &str| {
            status
                .get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|v| is_id(v))
                .map(str::to_string)
        };
        let progress = status
            .get("progress")
            .and_then(serde_json::Value::as_f64)
            .filter(|p| p.is_finite())
            .map(clamp_fraction);
        let load = Self {
            phase: id("phase"),
            step: id("step"),
            progress,
        };
        (load != Self::default()).then_some(load)
    }
}

fn is_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `p` clamped to 0–1, as the `f32` the wire carries. A fraction of a progress
/// bar loses nothing a user could see in the narrowing.
#[allow(clippy::cast_possible_truncation)]
fn clamp_fraction(p: f64) -> f32 {
    p.clamp(0.0, 1.0) as f32
}

#[cfg(test)]
mod tests {
    use super::{LoadProgress, phase, step};
    use serde_json::json;

    /// The fields a backend sends while loading come through as it sent them.
    #[test]
    fn reads_the_fields_a_loading_backend_reports() {
        let load = LoadProgress::from_status(&json!({
            "status": "success",
            "state": "loading",
            "phase": "initial_setup",
            "step": "building_kernels",
            "progress": 0.5,
        }))
        .expect("the status carries load fields");
        assert_eq!(load.phase.as_deref(), Some(phase::INITIAL_SETUP));
        assert_eq!(load.step.as_deref(), Some(step::BUILDING_KERNELS));
        assert_eq!(load.progress, Some(0.5));
    }

    /// A backend that says nothing about its load yields nothing to relay,
    /// which is every backend written before these fields existed.
    #[test]
    fn a_status_without_load_fields_yields_none() {
        assert_eq!(
            LoadProgress::from_status(&json!({ "status": "success", "state": "loading" })),
            None
        );
    }

    /// Only the fields that pass are kept, so one bad value does not cost the
    /// others.
    #[test]
    fn a_bad_field_is_dropped_and_the_rest_kept() {
        let load = LoadProgress::from_status(&json!({
            "phase": "<b>Setting up</b>",
            "step": "warming_up",
            "progress": "half",
        }))
        .expect("the step passes");
        assert_eq!(load.phase, None, "markup is not an id");
        assert_eq!(load.step.as_deref(), Some(step::WARMING_UP));
        assert_eq!(load.progress, None, "a string is not a fraction");

        let long = "a".repeat(65);
        assert_eq!(
            LoadProgress::from_status(&json!({ "step": long })),
            None,
            "an over-long id is dropped"
        );
    }

    /// A fraction past either end is pulled back to it rather than shown as a
    /// bar over-full or running backwards.
    #[test]
    fn progress_is_clamped_to_a_fraction() {
        let over = LoadProgress::from_status(&json!({ "progress": 1.7 })).unwrap();
        assert_eq!(over.progress, Some(1.0));
        let under = LoadProgress::from_status(&json!({ "progress": -0.2 })).unwrap();
        assert_eq!(under.progress, Some(0.0));
    }

    /// What goes out on the wire leaves out what the backend did not say.
    #[test]
    fn absent_fields_are_left_off_the_wire() {
        let load = LoadProgress {
            step: Some(step::LOADING_WEIGHTS.to_string()),
            ..LoadProgress::default()
        };
        assert_eq!(
            serde_json::to_value(&load).unwrap(),
            json!({ "step": "loading_weights" })
        );
    }
}
