// SPDX-License-Identifier: GPL-3.0-only
//! The event bus a daemon publishes on, and the `GET /events` stream that
//! serves it.
//!
//! A daemon's topics are the core ones every daemon publishes
//! (`frequency_bands`, `daemon_status_changed`, `download_progress`,
//! `registry_install`) plus its own. [`event_topics!`] takes the product's
//! rows and generates, in the daemon's crate, a `Topic` enum with the
//! wire-name and scope of each, an `EventBus` holding one broadcast channel
//! per topic, and the `AnyReceiver` a subscription reads from — core rows
//! included. The daemon adds a publish method per topic of its own.
//!
//! [`stream`] is the body of a daemon's `/events` handler. The handler stays
//! the daemon's, since its documentation lists the daemon's topics.
//!
//! `tokio::sync::broadcast` is multi-subscriber by construction: every
//! `subscribe()` call returns an independent `Receiver` reading into the
//! same ring buffer at its own position. A slow subscriber gets
//! `RecvError::Lagged(n)` and skips ahead — the producer never blocks, and
//! other subscribers are unaffected.

use crate::auth::tokens::TokenStore;
use crate::auth::{AuthContext, PeerIdentity, resolve_peer_identity};
use crate::http::PeerInfo;
use crate::http::responses::{invalid_session, reason, scope_denied};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Serialize;
use std::future::Future;
use tokio::sync::broadcast;

/// What [`event_topics!`] expands to names, re-exported so a daemon needs no
/// dependency of its own on them.
#[doc(hidden)]
pub mod __private {
    pub use serde_json;
    pub use tokio::sync::broadcast;
}

/// Ring-buffer depth of a high-rate topic (`frequency_bands`). These bound the
/// *replay window* — how far behind a slow subscriber can fall before the
/// broadcast channel starts dropping its oldest entries. Memory is
/// `capacity × sizeof::<Event>` per channel total, **not** multiplied by
/// subscriber count.
pub const AUDIO_BUF_CAPACITY: usize = 256;

/// Ring-buffer depth of every other topic. See [`AUDIO_BUF_CAPACITY`].
pub const STATE_BUF_CAPACITY: usize = 32;

// ---------- Core payloads -----------------------------------------------------

/// `frequency_bands` — the audio's spectrum, for visualizers. The `f32` bands
/// ride base64-encoded (little-endian) in `bands_b64`, so the JSON envelope
/// is self-contained.
#[derive(Clone, Debug, Serialize)]
pub struct FrequencyBandsEvent {
    pub bands_b64: String,
    pub sample_rate: f32,
    pub total_energy: f32,
}

impl FrequencyBandsEvent {
    /// The event for `bands`.
    #[must_use]
    pub fn new(bands: &[f32], sample_rate: f32, total_energy: f32) -> Self {
        Self {
            bands_b64: encode_f32_b64(bands),
            sample_rate,
            total_energy,
        }
    }
}

/// `daemon_status_changed` carries a heterogeneous payload: the `status`
/// discriminator selects between `loading_model`, `ready`,
/// `model_switched`, `switching_device`, `device_switch_error`, etc.
/// Each variant has its own keys (`model_loaded`, `actual_device`,
/// `target_device`, …), so the bus carries it as JSON.
pub type DaemonStatusChangedEvent = serde_json::Value;

/// `download_progress` — the keys of the product's `DownloadProgress` plus
/// a `timestamp`, carried as JSON for the same reason.
pub type DownloadProgressEvent = serde_json::Value;

/// `registry_install` — a serialized registry event (`install.progress`,
/// `install.completed`, `install.failed`, `refresh.completed`,
/// `refresh.failed`), carried as JSON.
pub type RegistryInstallEvent = serde_json::Value;

/// Encode an `f32` slice as little-endian bytes, then base64. Matches the
/// shape decoders expect on the widget side.
#[must_use]
pub fn encode_f32_b64(samples: &[f32]) -> String {
    let mut bytes = Vec::with_capacity(samples.len() * 4);
    for &s in samples {
        bytes.extend_from_slice(&s.to_le_bytes());
    }
    B64.encode(&bytes)
}

// ---------- What the generated types implement ----------------------------------

/// One of a daemon's topics. Implemented by the `Topic` enum
/// [`event_topics!`] generates.
pub trait Topic: Copy + Eq + std::fmt::Debug + Send + Sync + 'static {
    /// Wire name (the SSE `event:` line and the `?topics=` query value).
    fn as_str(self) -> &'static str;
    /// Parse a wire name back into a topic; `None` for unknown strings.
    fn from_wire(s: &str) -> Option<Self>;
    /// The scope a token must hold to subscribe.
    fn required_scope(self) -> &'static str;
}

/// A subscription to one topic. Implemented by the generated `AnyReceiver`.
pub trait TopicReceiver: Send + 'static {
    /// The next event as `(wire_name, json_data)`.
    fn recv_json_str(
        &mut self,
    ) -> impl Future<Output = Result<(&'static str, String), broadcast::error::RecvError>> + Send;
}

/// Something to subscribe to. Implemented by the generated `EventBus`.
pub trait EventSource {
    type Topic: Topic;
    type Receiver: TopicReceiver;
    /// An independent receiver for `topic`.
    fn subscribe(&self, topic: Self::Topic) -> Self::Receiver;
}

/// Publishing on the core topics — what shared daemon code (downloads,
/// registry installs) publishes through, without knowing the product's bus.
/// Implemented by the generated `EventBus`. Every publish is synchronous and
/// best-effort: with no subscriber, the event is dropped.
pub trait CoreEvents: Send + Sync {
    fn publish_frequency_bands(&self, bands: &[f32], sample_rate: f32, total_energy: f32);
    fn publish_daemon_status_changed(&self, data: DaemonStatusChangedEvent);
    fn publish_download_progress(&self, data: DownloadProgressEvent);
    fn publish_registry_install(&self, data: RegistryInstallEvent);
}

// ---------- The topic table ------------------------------------------------------

/// Generate a daemon's per-topic surface from its own topic rows, with the
/// core topics added: the `Topic` enum and its `as_str` / `from_wire` /
/// `required_scope` mappings, the `EventBus` senders with `new`,
/// `subscribe` and the core `publish_*` methods, and the `AnyReceiver`
/// wrapper. Adding a topic is one row; the mappings can't drift out of sync.
///
/// Invoke it once, in the module that should hold the three types:
///
/// ```ignore
/// super_engine_daemon::event_topics! {
///     /// Whether speech is currently coming out of the speakers.
///     SpeakingState {
///         wire: "speaking_state", scope: "playback_events",
///         field: speaking_state, payload: SpeakingStateEvent,
///         capacity: super_engine_daemon::events::STATE_BUF_CAPACITY,
///     },
/// }
///
/// impl EventBus {
///     pub fn publish_speaking_state(&self, event: SpeakingStateEvent) {
///         let _ = self.speaking_state.send(event);
///     }
/// }
/// ```
#[macro_export]
macro_rules! event_topics {
    (
        $(
            $(#[$vmeta:meta])*
            $Variant:ident {
                wire: $wire:literal,
                scope: $scope:literal,
                field: $field:ident,
                payload: $Payload:ty,
                capacity: $cap:expr,
            }
        ),* $(,)?
    ) => {
        $crate::__event_topics! {
            $(
                $(#[$vmeta])*
                $Variant {
                    wire: $wire, scope: $scope, field: $field,
                    payload: $Payload, capacity: $cap,
                },
            )*
            /// The audio's frequency bands, for visualizers.
            FrequencyBands {
                wire: "frequency_bands", scope: "audio_visualization",
                field: frequency_bands, payload: $crate::events::FrequencyBandsEvent,
                capacity: $crate::events::AUDIO_BUF_CAPACITY,
            },
            /// Model loads, switches and device changes.
            DaemonStatusChanged {
                wire: "daemon_status_changed", scope: "daemon_status",
                field: daemon_status_changed,
                payload: $crate::events::DaemonStatusChangedEvent,
                capacity: $crate::events::STATE_BUF_CAPACITY,
            },
            /// Model download progress.
            DownloadProgress {
                wire: "download_progress", scope: "daemon_status",
                field: download_progress, payload: $crate::events::DownloadProgressEvent,
                capacity: $crate::events::STATE_BUF_CAPACITY,
            },
            /// Registry install / refresh progress.
            RegistryInstall {
                wire: "registry_install", scope: "daemon_status",
                field: registry_install, payload: $crate::events::RegistryInstallEvent,
                capacity: $crate::events::STATE_BUF_CAPACITY,
            },
        }
    };
}

/// The expansion behind [`event_topics!`], once the core rows are added.
#[doc(hidden)]
#[macro_export]
macro_rules! __event_topics {
    (
        $(
            $(#[$vmeta:meta])*
            $Variant:ident {
                wire: $wire:literal,
                scope: $scope:literal,
                field: $field:ident,
                payload: $Payload:ty,
                capacity: $cap:expr,
            },
        )+
    ) => {
        /// Set of topics the daemon emits over `GET /events`. The `as_str`
        /// mapping is the wire name used in the `event:` line of each SSE
        /// frame; each topic's [`Topic::required_scope`] gates who may
        /// subscribe to it.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Topic {
            $( $(#[$vmeta])* $Variant, )+
        }

        impl Topic {
            /// Every topic, core ones included.
            // Generated for every daemon; one that never lists its topics
            // should not be warned about it.
            #[allow(dead_code)]
            pub const ALL: &'static [Self] = &[$( Self::$Variant, )+];

            /// Wire name (matches the SSE `event:` line and the `?topics=` query value).
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$Variant => $wire, )+ }
            }

            /// Parse a wire-name back into a `Topic`. Returns `None` for unknown
            /// strings; callers translate that to `400 invalid_topic`. Named
            /// `from_wire` rather than `from_str` to avoid confusion with the
            /// `std::str::FromStr` trait method.
            #[must_use]
            pub fn from_wire(s: &str) -> Option<Self> {
                match s {
                    $( $wire => Some(Self::$Variant), )+
                    _ => None,
                }
            }

            /// The scope a token must hold to subscribe to this topic on
            /// `GET /events`. Single source of truth for the topic→scope gate.
            #[must_use]
            pub const fn required_scope(self) -> &'static str {
                match self { $( Self::$Variant => $scope, )+ }
            }
        }

        impl $crate::events::Topic for Topic {
            fn as_str(self) -> &'static str {
                Self::as_str(self)
            }
            fn from_wire(s: &str) -> Option<Self> {
                Self::from_wire(s)
            }
            fn required_scope(self) -> &'static str {
                Self::required_scope(self)
            }
        }

        /// One `broadcast::Sender` per topic. Clones share the underlying
        /// senders.
        #[derive(Clone)]
        pub struct EventBus {
            $( $field: $crate::events::__private::broadcast::Sender<$Payload>, )+
        }

        impl Default for EventBus {
            fn default() -> Self {
                $( let ($field, _) = $crate::events::__private::broadcast::channel($cap); )+
                Self { $( $field, )+ }
            }
        }

        impl EventBus {
            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }

            /// Subscribe to a topic. Each call returns an independent
            /// receiver — multiple widgets can subscribe to the same topic
            /// concurrently.
            #[must_use]
            pub fn subscribe(&self, topic: Topic) -> AnyReceiver {
                match topic {
                    $( Topic::$Variant => AnyReceiver::$Variant(self.$field.subscribe()), )+
                }
            }

            /// Publish a `frequency_bands` event.
            pub fn publish_frequency_bands(&self, bands: &[f32], sample_rate: f32, total_energy: f32) {
                let _ = self.frequency_bands.send($crate::events::FrequencyBandsEvent::new(
                    bands,
                    sample_rate,
                    total_energy,
                ));
            }

            /// Publish a `daemon_status_changed` event. Subscribers need the
            /// `daemon_status` scope.
            pub fn publish_daemon_status_changed(
                &self,
                data: $crate::events::DaemonStatusChangedEvent,
            ) {
                let _ = self.daemon_status_changed.send(data);
            }

            /// Publish a `download_progress` event: the keys of the
            /// product's `DownloadProgress` plus a `timestamp`. Subscribers
            /// need the `daemon_status` scope.
            pub fn publish_download_progress(&self, data: $crate::events::DownloadProgressEvent) {
                let _ = self.download_progress.send(data);
            }

            /// Publish a `registry_install` event. Subscribers need the
            /// `daemon_status` scope.
            pub fn publish_registry_install(&self, data: $crate::events::RegistryInstallEvent) {
                let _ = self.registry_install.send(data);
            }
        }

        impl $crate::events::CoreEvents for EventBus {
            fn publish_frequency_bands(&self, bands: &[f32], sample_rate: f32, total_energy: f32) {
                Self::publish_frequency_bands(self, bands, sample_rate, total_energy);
            }
            fn publish_daemon_status_changed(&self, data: $crate::events::DaemonStatusChangedEvent) {
                Self::publish_daemon_status_changed(self, data);
            }
            fn publish_download_progress(&self, data: $crate::events::DownloadProgressEvent) {
                Self::publish_download_progress(self, data);
            }
            fn publish_registry_install(&self, data: $crate::events::RegistryInstallEvent) {
                Self::publish_registry_install(self, data);
            }
        }

        impl $crate::events::EventSource for EventBus {
            type Topic = Topic;
            type Receiver = AnyReceiver;
            fn subscribe(&self, topic: Topic) -> AnyReceiver {
                Self::subscribe(self, topic)
            }
        }

        /// Heterogeneous receiver wrapper so the `/events` handler can hold a
        /// receiver per requested topic and forward each the same way. Each
        /// variant carries its typed `broadcast::Receiver`.
        pub enum AnyReceiver {
            $( $Variant($crate::events::__private::broadcast::Receiver<$Payload>), )+
        }

        impl AnyReceiver {
            /// Receive the next event for this topic as `(wire_name, json_data)`,
            /// where `json_data` is the serialized SSE `data:` payload ready for
            /// the frame formatter. The typed topics are serialized straight to
            /// their JSON string, with no intermediate `serde_json::Value`.
            ///
            /// # Errors
            /// `RecvError::Lagged(n)` when the receiver fell behind the channel
            /// capacity (the SSE stream logs and resyncs); `RecvError::Closed`
            /// when all senders have been dropped.
            pub async fn recv_json_str(
                &mut self,
            ) -> Result<(&'static str, String), $crate::events::__private::broadcast::error::RecvError> {
                match self {
                    $(
                        Self::$Variant(rx) => {
                            let evt = rx.recv().await?;
                            Ok((
                                Topic::$Variant.as_str(),
                                $crate::events::__private::serde_json::to_string(&evt)
                                    .unwrap_or_default(),
                            ))
                        }
                    )+
                }
            }

            /// [`recv_json_str`](Self::recv_json_str) parsed back into a
            /// `serde_json::Value`, for tests that assert on structured fields.
            ///
            /// # Errors
            /// See [`recv_json_str`](Self::recv_json_str).
            #[cfg(test)]
            #[allow(dead_code)]
            pub async fn recv_json(
                &mut self,
            ) -> Result<
                (&'static str, $crate::events::__private::serde_json::Value),
                $crate::events::__private::broadcast::error::RecvError,
            > {
                let (name, json) = self.recv_json_str().await?;
                Ok((
                    name,
                    $crate::events::__private::serde_json::from_str(&json).unwrap_or_default(),
                ))
            }
        }

        impl $crate::events::TopicReceiver for AnyReceiver {
            fn recv_json_str(
                &mut self,
            ) -> impl ::std::future::Future<
                Output = Result<
                    (&'static str, String),
                    $crate::events::__private::broadcast::error::RecvError,
                >,
            > + Send {
                Self::recv_json_str(self)
            }
        }
    };
}

// ---------- GET /events ------------------------------------------------------------

/// The query `GET /events` takes.
#[derive(serde::Deserialize)]
pub struct EventsQuery {
    /// Comma-separated topic names. Empty / missing → 400 `invalid_topic`.
    pub topics: Option<String>,
}

/// Per-connection SSE channel capacity. The channel serializes every frame
/// (all topic forwarders + keepalive + revocation) into the response body. A
/// widget that stops draining its side would otherwise buffer `frequency_bands`
/// frames — emitted many times per second — without bound; capping the channel
/// and dropping frames once it fills sheds that load instead (Tier 3 #8). The
/// dominant volume is visualization frames, so those are what overflow drops in
/// practice; low-rate control frames only shed for an already-stalled reader,
/// which the keepalive / exe-watch task then tears down.
const SSE_CHANNEL_CAPACITY: usize = 256;

/// Convenience alias for the bounded per-connection SSE sender.
type SseSender = tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>;

/// Build the raw bytes of one SSE `event: <name>\ndata: <json>\n\n` frame from an
/// already-serialized JSON `data:` string. `data` must be single-line (no raw
/// newlines) — `serde_json::to_string` guarantees this. This is the canonical
/// framer, used with the string [`TopicReceiver::recv_json_str`] produces and
/// by a daemon's own event streams.
#[must_use]
pub fn sse_frame(event: &str, data: &str) -> axum::body::Bytes {
    let mut bytes = format!("event: {event}\ndata: ").into_bytes();
    bytes.extend_from_slice(data.as_bytes());
    bytes.extend_from_slice(b"\n\n");
    axum::body::Bytes::from(bytes)
}

/// Try to enqueue an SSE frame on the bounded per-connection channel. Returns
/// `false` only when the receiver is gone (client disconnected), so the caller
/// tears down. A full channel drops the frame — the reader is stalled, so shed
/// it — and returns `true`.
fn try_emit_sse_event(tx: &SseSender, event: &str, data: &str) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    match tx.try_send(Ok(sse_frame(event, data))) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            log::warn!("widget SSE backpressured; dropped a {event} frame");
            true
        }
        Err(TrySendError::Closed(_)) => false,
    }
}

fn invalid_topic(reason: &str) -> Response {
    let body = serde_json::json!({
        "status":  "error",
        "message": "invalid_topic",
        "data":    { "reason": reason },
    });
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// The body of a daemon's `GET /events?topics=...` handler.
///
/// Opens a stream that runs until the client disconnects, the daemon shuts
/// down, or `exe_changed` triggers a revoked event. Each requested topic gets
/// a per-connection receiver which runs in its own forwarder task — so all
/// subscribers receive events independently and a slow widget never starves
/// a fast one (and vice versa).
///
/// The forwarder tasks share a `CancellationToken` with the keepalive +
/// exe-watch task, so any of `client disconnect / exe_changed / shutdown`
/// cleanly tears the whole subscription down.
///
/// `ctx` and `peer` are what the auth guard and the listener attached to the
/// request. Refuses with `400 invalid_topic` for a missing, empty or unknown
/// topic, and `403 scope_denied` when the token lacks the scope for any
/// requested topic.
pub fn stream<S: EventSource>(
    source: &S,
    topics: Option<&str>,
    ctx: Option<AuthContext>,
    peer: Option<&PeerInfo>,
    tokens: &TokenStore,
) -> Response {
    let requested: Vec<S::Topic> = match parse_topics(topics) {
        Ok(t) => t,
        Err(reason) => return invalid_topic(&reason),
    };

    // Auth context — should always be present after middleware ran, but
    // we degrade gracefully if it isn't (treat as missing session).
    let Some(ctx) = ctx else {
        return invalid_session(reason::UNKNOWN);
    };

    // Each requested topic is gated by the scope that grants it. If the
    // token is missing the scope for any requested topic, the whole
    // subscription is refused before it opens.
    if requested
        .iter()
        .any(|t| !ctx.meta.scopes.iter().any(|s| s == t.required_scope()))
    {
        return scope_denied();
    }

    // Bounded mpsc that serializes all SSE writes (broadcast forwarders +
    // keepalive + revocation). Bounded so a stalled reader sheds frames instead
    // of buffering without limit — see [`SSE_CHANNEL_CAPACITY`].
    let (sse_tx, sse_rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(
        SSE_CHANNEL_CAPACITY,
    );

    // Subscribe BEFORE emitting `subscribed`. Subscribing creates the
    // broadcast::Receiver that captures any event fired from this
    // point on — and once we send the `subscribed` ack the client is
    // entitled to assume every subsequent event reaches it. Doing the
    // ack first would leave a gap where events fire and are missed
    // even though the client believes the subscription is live.
    let topic_names: Vec<&'static str> = requested.iter().map(|t| t.as_str()).collect();
    let cancel = tokio_util::sync::CancellationToken::new();
    for topic in &requested {
        let rx = source.subscribe(*topic);
        spawn_topic_forwarder(rx, sse_tx.clone(), cancel.clone());
    }

    // Now that the receivers exist, ack the client. The channel is fresh so
    // this frame always has room.
    let _ = try_emit_sse_event(
        &sse_tx,
        "subscribed",
        &serde_json::json!({
            "client_id": uuid::Uuid::new_v4().to_string(),
            "subscribed_to": topic_names,
        })
        .to_string(),
    );

    spawn_events_keepalive_and_exe_watch(
        sse_tx.clone(),
        cancel,
        peer.and_then(|p| p.pid),
        tokens.clone(),
        ctx.token,
        ctx.meta.grantee,
    );

    // The handler's own `sse_tx` clone is dropped here. The forwarders
    // and the timer task own the remaining clones; once they all
    // finish, the mpsc receiver yields None and the response body ends.
    drop(sse_tx);

    let stream = tokio_stream::wrappers::ReceiverStream::new(sse_rx);
    let body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(body)
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "application/json")],
                String::from("{\"status\":\"error\"}"),
            )
                .into_response()
        })
}

/// Parse the `?topics=` query string into a deduplicated list of topics.
/// Returns the raw bad-topic name (or `"missing_topics"` for missing /
/// empty queries) on the `Err` arm so the caller can produce the
/// matching `400 invalid_topic` response.
fn parse_topics<T: Topic>(topics: Option<&str>) -> Result<Vec<T>, String> {
    let csv = match topics {
        Some(s) if !s.is_empty() => s,
        _ => return Err("missing_topics".to_string()),
    };
    let mut requested: Vec<T> = Vec::new();
    for raw in csv.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        match T::from_wire(raw) {
            Some(t) if !requested.contains(&t) => requested.push(t),
            Some(_) => {} // duplicate
            None => return Err(raw.to_string()),
        }
    }
    if requested.is_empty() {
        return Err("missing_topics".to_string());
    }
    Ok(requested)
}

/// Spawn a per-topic forwarder. Reads from the broadcast receiver and
/// writes each event as an SSE frame. Exits on cancel, on a closed
/// channel, or when the SSE response body has been dropped.
fn spawn_topic_forwarder<R: TopicReceiver>(
    mut rx: R,
    tx: SseSender,
    cancel: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                res = rx.recv_json_str() => {
                    match res {
                        Ok((name, payload)) => {
                            if !try_emit_sse_event(&tx, name, &payload) {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            log::warn!("widget SSE lagged: dropped {n} events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    });
}

/// Spawn the timer task that drives keep-alive comments and the
/// periodic exe-path check. On `exe_changed` the task emits a
/// `revoked` event, calls `TokenStore::revoke`, and triggers the
/// shared `cancel` token to tear down the rest of the subscription.
fn spawn_events_keepalive_and_exe_watch(
    tx: SseSender,
    cancel: tokio_util::sync::CancellationToken,
    peer_pid: Option<u32>,
    tokens: TokenStore,
    token_str: String,
    stored: PeerIdentity,
) {
    use tokio::time::{Duration, MissedTickBehavior, interval};

    tokio::spawn(async move {
        // Both timers are 30 s (cheap), aligned by `MissedTickBehavior::Skip`
        // so a temporarily-blocked task doesn't accumulate stale ticks.
        let mut keepalive = interval(Duration::from_secs(30));
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);
        keepalive.tick().await; // immediate first tick — discard
        let mut exe_watch = interval(Duration::from_secs(30));
        exe_watch.set_missed_tick_behavior(MissedTickBehavior::Skip);
        exe_watch.tick().await;

        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                _ = keepalive.tick() => {
                    // Only a gone receiver (client disconnected) tears down; a
                    // full channel means a stalled-but-live reader, so drop this
                    // heartbeat rather than cancel.
                    use tokio::sync::mpsc::error::TrySendError;
                    if let Err(TrySendError::Closed(_)) =
                        tx.try_send(Ok(axum::body::Bytes::from_static(b": keepalive\n\n")))
                    {
                        cancel.cancel();
                        break;
                    }
                }
                _ = exe_watch.tick() => {
                    // No pid means a web subscriber, which has no binary to
                    // watch: its identity is an origin, and an origin cannot
                    // be swapped on disk mid-stream. What *can* change is the
                    // user's allowlist, and this watch does not see that — a
                    // stream opened while an origin was allowed outlives its
                    // removal, until the client disconnects.
                    let Some(pid) = peer_pid else { continue; };
                    // Re-resolve the whole identity, not just the path: a
                    // sandboxed peer's path is one every sandbox can share, so
                    // comparing paths alone would miss a swap between them.
                    let current = resolve_peer_identity(
                        Some(&PeerInfo::unix(Some(pid), None)),
                        "events exe-watch",
                    );
                    if current.as_ref().is_some_and(|c| *c == stored) {
                        continue;
                    }
                    log::info!(
                        "widget exe_changed on pid {pid}: stored={} current={}; revoking session",
                        stored.describe(),
                        current.as_ref().map_or_else(
                            || "<unidentifiable>".to_string(),
                            PeerIdentity::describe,
                        ),
                    );
                    let _ = try_emit_sse_event(
                        &tx,
                        "revoked",
                        &serde_json::json!({ "reason": "exe_changed" }).to_string(),
                    );
                    tokens.revoke(&token_str);
                    cancel.cancel();
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{AUDIO_BUF_CAPACITY, B64, CoreEvents, STATE_BUF_CAPACITY, encode_f32_b64};
    use base64::Engine as _;
    use serde::Serialize;
    use tokio::sync::broadcast;

    /// A product topic, to show the product rows and the core rows together.
    #[derive(Clone, Debug, Serialize)]
    pub struct ChimeEvent {
        pub loud: bool,
    }

    crate::event_topics! {
        /// A product's own topic.
        Chime {
            wire: "chime", scope: "chime_events",
            field: chime, payload: ChimeEvent, capacity: STATE_BUF_CAPACITY,
        },
    }

    impl EventBus {
        fn publish_chime(&self, loud: bool) {
            let _ = self.chime.send(ChimeEvent { loud });
        }
    }

    fn f32_slice_from_b64(b64: &str) -> Vec<f32> {
        let bytes = B64.decode(b64).expect("valid base64");
        bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    #[tokio::test]
    async fn a_product_topic_round_trips() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe(Topic::Chime);
        bus.publish_chime(true);
        let (topic, payload) = rx.recv_json().await.expect("should receive");
        assert_eq!(topic, "chime");
        assert_eq!(payload["loud"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn fan_out_to_three_subscribers() {
        let bus = EventBus::new();
        let mut rx_a = bus.subscribe(Topic::FrequencyBands);
        let mut rx_b = bus.subscribe(Topic::FrequencyBands);
        let mut rx_c = bus.subscribe(Topic::FrequencyBands);

        bus.publish_frequency_bands(&[1.0, 2.0, 3.0], 16_000.0, 4.5);

        for rx in [&mut rx_a, &mut rx_b, &mut rx_c] {
            let (topic, payload) = rx.recv_json().await.expect("should receive");
            assert_eq!(topic, "frequency_bands");
            let bands = f32_slice_from_b64(payload["bands_b64"].as_str().unwrap());
            assert_eq!(bands, vec![1.0, 2.0, 3.0]);
            let total = payload["total_energy"].as_f64().unwrap();
            assert!((total - 4.5).abs() < 1e-6);
        }
    }

    #[tokio::test]
    async fn slow_subscriber_lags_without_blocking_others() {
        // After overflow there's nothing publishing, so we drain
        // non-blockingly (`try_recv`) — calling `recv().await` on an
        // empty channel with no senders dropped would block forever.
        let bus = EventBus::new();
        let AnyReceiver::Chime(mut fast_rx) = bus.subscribe(Topic::Chime) else {
            unreachable!("subscribe(Chime) returns the matching variant")
        };
        let AnyReceiver::Chime(mut slow_rx) = bus.subscribe(Topic::Chime) else {
            unreachable!("subscribe(Chime) returns the matching variant")
        };

        // Push enough events to overflow the STATE_BUF_CAPACITY-sized ring.
        for i in 0..(STATE_BUF_CAPACITY * 2) {
            bus.publish_chime(i % 2 == 0);
        }

        // Fast receiver: drain non-blockingly until empty. Tolerate a
        // single `Lagged` (overflow recovery) but expect to ultimately
        // receive several values.
        let mut fast_received = 0;
        loop {
            match fast_rx.try_recv() {
                Ok(_) => fast_received += 1,
                Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(e) => panic!("fast receiver closed: {e:?}"),
            }
        }
        assert!(
            fast_received >= STATE_BUF_CAPACITY,
            "fast receiver got {fast_received}; expected at least capacity ({STATE_BUF_CAPACITY})"
        );

        // Slow receiver: never read until after overflow → first read
        // must report Lagged.
        let first = slow_rx.try_recv();
        assert!(
            matches!(first, Err(broadcast::error::TryRecvError::Lagged(_))),
            "expected Lagged on first try_recv after overflow, got {first:?}"
        );
        // After acknowledging the lag, subsequent reads succeed against
        // the still-buffered tail.
        let mut slow_after_lag = 0;
        loop {
            match slow_rx.try_recv() {
                Ok(_) => slow_after_lag += 1,
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(e) => panic!("slow receiver closed: {e:?}"),
            }
        }
        assert!(
            slow_after_lag > 0,
            "slow receiver should resync after Lagged"
        );
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_silent() {
        let bus = EventBus::new();
        // No subscriber — the call must not panic or propagate.
        bus.publish_download_progress(serde_json::json!({ "percentage": 1.0 }));
    }

    #[test]
    fn topic_round_trips_through_str() {
        for &t in Topic::ALL {
            assert_eq!(Topic::from_wire(t.as_str()), Some(t));
        }
        assert_eq!(Topic::from_wire("not_a_topic"), None);
    }

    /// Shared code publishes through [`CoreEvents`] without knowing the
    /// product's bus, and a subscriber to the product's bus receives it.
    #[tokio::test]
    async fn the_core_topics_publish_through_the_trait() {
        let bus = EventBus::new();
        let mut status_rx = bus.subscribe(Topic::DaemonStatusChanged);
        let mut prog_rx = bus.subscribe(Topic::DownloadProgress);
        let mut install_rx = bus.subscribe(Topic::RegistryInstall);

        let events: &dyn CoreEvents = &bus;
        events.publish_daemon_status_changed(serde_json::json!({
            "status": "ready",
            "model_loaded": true,
        }));
        events.publish_download_progress(serde_json::json!({
            "model_name": "tiny",
            "percentage": 42.5,
        }));
        events.publish_registry_install(serde_json::json!({ "kind": "install.completed" }));

        let (topic, payload) = status_rx.recv_json().await.expect("daemon status");
        assert_eq!(topic, "daemon_status_changed");
        assert_eq!(payload["status"], serde_json::json!("ready"));
        assert_eq!(payload["model_loaded"], serde_json::json!(true));

        let (topic, payload) = prog_rx.recv_json().await.expect("download progress");
        assert_eq!(topic, "download_progress");
        assert_eq!(payload["model_name"], serde_json::json!("tiny"));

        let (topic, _) = install_rx.recv_json().await.expect("registry install");
        assert_eq!(topic, "registry_install");
    }

    #[test]
    fn b64_round_trip_preserves_f32_slice() {
        let original = vec![0.0_f32, -1.5, 2.5, f32::INFINITY, f32::NEG_INFINITY];
        let encoded = encode_f32_b64(&original);
        let decoded = f32_slice_from_b64(&encoded);
        assert_eq!(decoded.len(), original.len());
        for (a, b) in decoded.iter().zip(original.iter()) {
            assert_eq!(a.to_bits(), b.to_bits());
        }
    }

    /// The core rows the macro adds must agree with the protocol's table of
    /// core topics, which is what clients check their subscriptions against.
    #[test]
    fn the_core_topics_match_the_protocol() {
        for &(wire, scope) in super_engine_protocol::scopes::CORE_TOPICS {
            let topic = Topic::from_wire(wire)
                .unwrap_or_else(|| panic!("core topic `{wire}` is missing from the bus"));
            assert_eq!(topic.required_scope(), scope, "{wire}");
        }
        assert_eq!(
            Topic::ALL.len(),
            super_engine_protocol::scopes::CORE_TOPICS.len() + 1,
            "the bus holds the core topics plus the product's one"
        );
        assert_eq!(Topic::Chime.required_scope(), "chime_events");
        let _ = AUDIO_BUF_CAPACITY;
    }
}

/// [`super::stream`]: what it refuses, and what a stream opens with.
#[cfg(test)]
mod stream_tests {
    use super::{STATE_BUF_CAPACITY, stream};
    use crate::auth::AuthContext;
    use crate::auth::identity::PeerIdentity;
    use crate::auth::tokens::{TokenMeta, TokenStore};
    use axum::http::StatusCode;
    use futures_util::StreamExt as _;
    use serde::Serialize;

    #[derive(Clone, Debug, Serialize)]
    pub struct ChimeEvent {
        pub loud: bool,
    }

    crate::event_topics! {
        Chime {
            wire: "chime", scope: "chime_events",
            field: chime, payload: ChimeEvent, capacity: STATE_BUF_CAPACITY,
        },
    }

    fn ctx(scopes: &[&str]) -> AuthContext {
        AuthContext {
            meta: TokenMeta {
                app_name: "Test".to_string(),
                scopes: scopes.iter().map(ToString::to_string).collect(),
                grantee: PeerIdentity::native("/usr/bin/test"),
                issued_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            },
            token: "token".to_string(),
        }
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn missing_or_unknown_topics_are_invalid() {
        let bus = EventBus::new();
        let tokens = TokenStore::default();
        for (topics, reason) in [
            (None, "missing_topics"),
            (Some(""), "missing_topics"),
            (Some(" , "), "missing_topics"),
            (Some("chime,nope"), "nope"),
        ] {
            let response = stream(&bus, topics, Some(ctx(&["chime_events"])), None, &tokens);
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{topics:?}");
            let body = body_text(response).await;
            assert!(body.contains("invalid_topic"), "{body}");
            assert!(body.contains(reason), "{topics:?}: {body}");
        }
    }

    /// One topic the token cannot see refuses the whole subscription.
    #[tokio::test]
    async fn a_topic_without_its_scope_refuses_the_stream() {
        let bus = EventBus::new();
        let tokens = TokenStore::default();
        let response = stream(
            &bus,
            Some("chime,download_progress"),
            Some(ctx(&["chime_events"])),
            None,
            &tokens,
        );
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(body_text(response).await.contains("scope_denied"));
    }

    /// The first frame acknowledges the topics, deduplicated, and events
    /// published after it arrive as frames named for their topic.
    #[tokio::test]
    async fn a_stream_opens_with_its_topics_then_carries_events() {
        let bus = EventBus::new();
        let tokens = TokenStore::default();
        let response = stream(
            &bus,
            Some("chime, chime,download_progress"),
            Some(ctx(&["chime_events", "daemon_status"])),
            None,
            &tokens,
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut frames = response.into_body().into_data_stream();

        let first = frames.next().await.expect("a frame").expect("readable");
        let first = String::from_utf8_lossy(&first);
        assert!(first.starts_with("event: subscribed\n"), "{first}");
        assert!(
            first.contains(r#""subscribed_to":["chime","download_progress"]"#),
            "{first}"
        );

        let _ = bus.chime.send(ChimeEvent { loud: false });
        let next = frames.next().await.expect("a frame").expect("readable");
        assert_eq!(
            String::from_utf8_lossy(&next),
            "event: chime\ndata: {\"loud\":false}\n\n"
        );
    }
}
