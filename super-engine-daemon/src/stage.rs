// SPDX-License-Identifier: GPL-3.0-only
//! A product's pipeline stages, and every load and unload of their models.
//!
//! A product runs one model per stage of its pipeline: Super Voice's speech
//! to text runs a transcription model and a post-processor, and its text to
//! speech a synthesis model. Each stage does the same things with its model:
//! load it at startup or on demand, switch it for another, reload it, move it
//! to another device, unload it, unload it when idle, and stop it at
//! shutdown. Each stage used to carry its own copy of those steps, and the
//! copies drifted apart: one stage was never unloaded when idle, one said
//! when a load failed and the others did not, one recovered from a failed
//! device change its own way.
//!
//! So a product only says what each of its stages is ([`Stage`]): the slot
//! holding its model, the model it is set to run, how to build one, how to
//! record a choice and how to tell its clients. Every load and unload is
//! written once, here ([`StageExt`]), and [`Stages`] does what is done to all
//! of a daemon's stages at once.
//!
//! Every load and unload runs as its own task, so a request dropped while it
//! waits (its client gave up or went away) does not stop it halfway, with a
//! backend started and nothing in the slot.

use crate::model_slot::{LoadTurn, ModelSlot, SlotModel};
use log::{info, warn};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// How often [`Stages::spawn_idle_unload`] looks for models gone idle.
pub const CHECK_EVERY: Duration = Duration::from_secs(5);

/// A model, as a stage selects it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelId {
    /// The model's name, as its backend serves it.
    pub name: String,
    /// The source of the backend serving it.
    pub source: String,
}

impl ModelId {
    /// The model `name`, served by the backend `source`.
    #[must_use]
    pub fn new(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: source.into(),
        }
    }
}

impl fmt::Display for ModelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// A model, as a stage holds it.
pub trait StageModel: SlotModel {
    /// Which model it is.
    fn id(&self) -> ModelId;

    /// The framework it runs on (`cpu`, `cuda`, …), as clients are told.
    fn device(&self) -> String;
}

/// What a stage tells its clients. A product publishes each as its own event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageEvent<'a> {
    /// A load of `model` started: at startup, on demand, for a switch or a
    /// reload.
    Loading { model: &'a ModelId },
    /// `model` is loaded and runs on `device`.
    Loaded { model: &'a ModelId, device: &'a str },
    /// The model was unloaded, on request or for being idle: the stage holds
    /// none.
    Unloaded,
    /// The load of `model` failed with `error`: the stage holds no model.
    LoadFailed { model: &'a ModelId, error: &'a str },
    /// The loaded `model` is moving from the framework `from` to `to`.
    SwitchingDevice {
        model: &'a ModelId,
        from: &'a str,
        to: &'a str,
    },
    /// `model` is loading on `device`, for a device switch or its recovery.
    LoadingOnDevice { model: &'a ModelId, device: &'a str },
    /// Moving `model` to `device` failed with `error`. The recovery follows.
    DeviceSwitchFailed {
        model: &'a ModelId,
        device: &'a str,
        error: &'a str,
    },
    /// After a device switch or its recovery, `model` runs on `device`. It
    /// was loaded for `preferred`, which it may have fallen back from.
    DeviceSwitched {
        model: &'a ModelId,
        device: &'a str,
        preferred: &'a str,
    },
}

/// One stage of a product's pipeline: what the product says about it. Every
/// load and unload of its model is [`StageExt`]'s.
///
/// A clone is the same stage: it is moved into the task each load runs as.
pub trait Stage: Clone + Send + Sync + 'static {
    /// The model the stage holds.
    type Model: StageModel;

    /// The slot holding the stage's model.
    fn slot(&self) -> &ModelSlot<Self::Model>;

    /// The model the stage is set to run: switched on, and pointed at a model
    /// that is installed. Otherwise why not, when that is worth logging.
    ///
    /// Read on every request that loads on demand, so it should not log.
    fn selected(&self) -> impl Future<Output = Result<ModelId, Option<String>>> + Send;

    /// Build `model` on `turn`, on `device` or, with `None`, on the framework
    /// its setting names. A model this stage does not run is refused.
    fn instantiate(
        &self,
        turn: &LoadTurn<'_, Self::Model>,
        model: &ModelId,
        device: Option<&str>,
    ) -> impl Future<Output = anyhow::Result<Self::Model>> + Send;

    /// How long the model may sit unused before it is unloaded, or `None` to
    /// keep it loaded. Read each time, so a change applies at once.
    fn idle_after(&self) -> impl Future<Output = Option<Duration>> + Send;

    /// Whether something under way will use the model, such as a recording
    /// or an utterance: it is not unloaded, and its idle time starts when
    /// that ends.
    fn in_use(&self) -> bool;

    /// Tell clients `event`.
    fn announce(&self, event: StageEvent<'_>);

    /// Record `model` as the one the stage runs, and switch the stage on.
    fn select(&self, model: &ModelId) -> impl Future<Output = ()> + Send;

    /// Switch the stage off, so nothing loads its model until a client asks
    /// again. Returns whether it was on.
    fn switch_off(&self) -> impl Future<Output = bool> + Send;

    /// Record `device` as the framework `model` loads on.
    fn set_device(&self, model: &ModelId, device: &str) -> impl Future<Output = ()> + Send;

    /// Completes when the daemon starts shutting down: a load then gives up.
    /// Only a shutdown after this call needs to complete it.
    fn shutdown_signal(&self) -> impl Future<Output = ()> + Send + 'static;
}

/// How a load ended.
#[derive(Debug)]
pub enum Load {
    /// `model` is loaded and runs on `device`.
    Loaded { model: ModelId, device: String },
    /// Nothing to load: the model asked for was loaded already, a reload
    /// found nothing loaded, or a load on demand found the slot filled or
    /// nothing selected.
    Unchanged,
    /// A request asked for since replaces the model anyway.
    Superseded,
    /// The daemon started shutting down first.
    Cancelled,
    /// The load of `model` failed: the stage holds no model.
    Failed {
        model: ModelId,
        error: anyhow::Error,
    },
}

/// How a device switch ended.
#[derive(Debug)]
pub enum DeviceSwitch {
    /// The model is not the one loaded: the device is recorded for its next
    /// load.
    Recorded,
    /// The model runs on `device`, the framework it landed on.
    Switched { device: String },
    /// The switch failed with `error`, and the model runs again on `device`.
    Recovered {
        error: anyhow::Error,
        device: String,
    },
    /// The switch failed with `error`, and so did loading the model again:
    /// the stage holds no model.
    Failed {
        error: anyhow::Error,
        recovery: anyhow::Error,
    },
    /// A request asked for since replaces the model anyway.
    Superseded,
    /// The daemon started shutting down first.
    Cancelled,
}

/// How an unload ended.
#[derive(Debug)]
pub enum Unload {
    /// The stage is switched off, and `model` was unloaded. `None` when the
    /// stage was on with no model in memory: one unloaded for being idle, or
    /// one whose load failed.
    Unloaded { model: Option<ModelId> },
    /// The stage was off and held nothing.
    NothingToUnload,
    /// A load asked for since replaces the model anyway.
    Superseded,
    /// The daemon started shutting down first.
    Cancelled,
}

/// Every load and unload of a [`Stage`]'s model, written once for every
/// stage.
pub trait StageExt: Stage {
    /// Record a use of the model and, when it is unloaded on idle, load the
    /// selected one if it is not in memory. Every request that runs the stage
    /// calls this first.
    ///
    /// Returns once the model is loaded or cannot be.
    ///
    /// # Errors
    /// The load failed: which model, and why. Finding nothing to load is not
    /// an error: the caller's own "no model loaded" check reports it.
    fn ensure_loaded(&self) -> impl Future<Output = Result<(), String>> + Send;

    /// Whether a request finding no model in memory loads one: the model is
    /// unloaded on idle, and one is selected.
    fn loads_on_demand(&self) -> impl Future<Output = bool> + Send;

    /// Load the selected model if the slot is empty, whatever the idle
    /// setting: at startup, on demand, or when idle unload is turned off.
    ///
    /// Waits for every load and unload in flight first, and loads only into
    /// a slot still empty after it: see [`ModelSlot::begin_load_if_empty`].
    /// The selection is read on the load's turn, so an unload that switched
    /// the stage off meanwhile is seen.
    fn load_selected(&self) -> impl Future<Output = Load> + Send;

    /// Run `model` in the stage, replacing what it runs.
    ///
    /// The choice is recorded before the load, so one that fails leaves it
    /// selected and not loaded, as a failed start does. Asking for the model
    /// already loaded changes nothing.
    fn switch_to(&self, model: ModelId) -> impl Future<Output = Load> + Send;

    /// Load the model in the stage again, in place, so a changed secret or
    /// option applies. Nothing when no model is loaded.
    fn reload(&self) -> impl Future<Output = Load> + Send;

    /// Move `model` to `device`. Its setting is recorded once it has loaded
    /// there, so a switch that fails leaves it as it was: a restart does not
    /// put the model on a device it cannot run on. On failure the model is
    /// loaded again on `fallback`, the framework its setting loads it on, on
    /// the same turn, so no other load lands in between.
    ///
    /// A model that is not the one loaded only has the device recorded.
    fn switch_device(
        &self,
        model: ModelId,
        device: String,
        fallback: String,
    ) -> impl Future<Output = DeviceSwitch> + Send;

    /// Unload the model and switch the stage off, so nothing loads it again
    /// until a client asks. A load in flight finishes first, and its model is
    /// the one unloaded: see [`ModelSlot::unload`].
    fn unload(&self) -> impl Future<Output = Unload> + Send;

    /// Unload the model if nothing has used it for `after`, keeping it
    /// selected. Returns whether it did.
    fn unload_if_idle(&self, after: Duration) -> impl Future<Output = bool> + Send;

    /// Stop the model as the daemon exits, after an idle unload still
    /// stopping its backend. Returns whether there was one.
    fn shutdown(&self) -> impl Future<Output = bool> + Send;
}

impl<S: Stage> StageExt for S {
    async fn ensure_loaded(&self) -> Result<(), String> {
        // Before the slot is read: an idle unload reads the time under the
        // slot's write lock, so a request that got this far is not unloaded
        // under it.
        self.slot().touch();
        if self.slot().is_loaded().await || self.idle_after().await.is_none() {
            return Ok(());
        }
        let loaded = self.load_selected().await;
        self.slot().touch();
        match loaded {
            Load::Failed { model, error } => Err(format!("{model} did not load: {error:#}")),
            _ => Ok(()),
        }
    }

    async fn loads_on_demand(&self) -> bool {
        self.idle_after().await.is_some() && self.selected().await.is_ok()
    }

    async fn load_selected(&self) -> Load {
        run(self, |stage| async move {
            let Some(turn) = stage.slot().begin_load_if_empty().await else {
                return Load::Unchanged;
            };
            let model = match stage.selected().await {
                Ok(model) => model,
                Err(why) => {
                    if let Some(why) = why {
                        info!("{why}");
                    }
                    return Load::Unchanged;
                }
            };
            load(&stage, turn, model).await
        })
        .await
        .unwrap_or(Load::Cancelled)
    }

    async fn switch_to(&self, model: ModelId) -> Load {
        if loaded(self).await.as_ref() == Some(&model) {
            return Load::Unchanged;
        }
        run(self, |stage| async move {
            stage.select(&model).await;
            let Some(turn) = stage.slot().begin_load().await else {
                return Load::Superseded;
            };
            load(&stage, turn, model).await
        })
        .await
        .unwrap_or(Load::Cancelled)
    }

    async fn reload(&self) -> Load {
        let Some(model) = loaded(self).await else {
            return Load::Unchanged;
        };
        run(self, |stage| async move {
            let Some(turn) = stage.slot().begin_load().await else {
                return Load::Superseded;
            };
            load(&stage, turn, model).await
        })
        .await
        .unwrap_or(Load::Cancelled)
    }

    async fn switch_device(
        &self,
        model: ModelId,
        device: String,
        fallback: String,
    ) -> DeviceSwitch {
        let from = self
            .slot()
            .read()
            .await
            .as_ref()
            .filter(|loaded| loaded.id() == model)
            .map(StageModel::device);
        let Some(from) = from else {
            self.set_device(&model, &device).await;
            return DeviceSwitch::Recorded;
        };
        run(self, |stage| async move {
            switch_device_on_turn(&stage, model, &device, &from, &fallback).await
        })
        .await
        .unwrap_or(DeviceSwitch::Cancelled)
    }

    async fn unload(&self) -> Unload {
        run(self, |stage| async move {
            let Some(unloaded) = stage.slot().unload().await else {
                return Unload::Superseded;
            };
            let model = unloaded.model.as_ref().map(StageModel::id);
            // While the slot is held, so no load on demand reads the stage as
            // still on.
            let was_on = stage.switch_off().await;
            if model.is_none() && !was_on {
                return Unload::NothingToUnload;
            }
            stage.announce(StageEvent::Unloaded);
            drop(unloaded);
            match &model {
                Some(model) => info!("Unloaded {model}"),
                None => info!("Switched off a stage with no model in memory"),
            }
            Unload::Unloaded { model }
        })
        .await
        .unwrap_or(Unload::Cancelled)
    }

    async fn unload_if_idle(&self, after: Duration) -> bool {
        if self.in_use() {
            self.slot().touch();
            return false;
        }
        self.slot()
            .unload_if_idle(after, |model| {
                info!(
                    "Unloaded {} after {}s idle; it loads again on demand",
                    model.id(),
                    after.as_secs()
                );
                self.announce(StageEvent::Unloaded);
            })
            .await
    }

    async fn shutdown(&self) -> bool {
        let Some(model) = self.slot().shutdown().await else {
            return false;
        };
        info!("Shutdown: stopped {} so its backend exits", model.id());
        true
    }
}

/// The model in `stage`'s slot now.
async fn loaded<S: Stage>(stage: &S) -> Option<ModelId> {
    stage.slot().read().await.as_ref().map(StageModel::id)
}

/// Run `op` on a clone of `stage` as its own task, so a caller that stops
/// waiting does not stop it halfway. `None` when the runtime is shutting
/// down.
async fn run<S, F, T>(stage: &S, op: impl FnOnce(S) -> F) -> Option<T>
where
    S: Stage,
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::spawn(op(stage.clone())).await {
        Ok(done) => Some(done),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(_) => None,
    }
}

/// Build `model` on `turn` and install it, telling clients how it went.
async fn load<S: Stage>(stage: &S, turn: LoadTurn<'_, S::Model>, model: ModelId) -> Load {
    let shutdown = stage.shutdown_signal();
    tokio::pin!(shutdown);
    stage.announce(StageEvent::Loading { model: &model });
    match build(stage, &turn, &model, None, shutdown).await {
        None => Load::Cancelled,
        Some(Ok(built)) => {
            let device = built.device();
            turn.install(built).await;
            info!("Loaded {model} on {device}");
            stage.announce(StageEvent::Loaded {
                model: &model,
                device: &device,
            });
            Load::Loaded { model, device }
        }
        Some(Err(error)) => {
            let shown = format!("{error:#}");
            warn!("Failed to load {model}: {shown}");
            // Before the turn ends, so the next load's announcement comes
            // after this one.
            stage.announce(StageEvent::LoadFailed {
                model: &model,
                error: &shown,
            });
            drop(turn);
            Load::Failed { model, error }
        }
    }
}

/// [`StageExt::switch_device`] once the model is known to be loaded.
async fn switch_device_on_turn<S: Stage>(
    stage: &S,
    model: ModelId,
    device: &str,
    from: &str,
    fallback: &str,
) -> DeviceSwitch {
    let shutdown = stage.shutdown_signal();
    tokio::pin!(shutdown);
    info!("Moving {model} from {from} to {device}");
    stage.announce(StageEvent::SwitchingDevice {
        model: &model,
        from,
        to: device,
    });
    // The model is taken out and stopped on this turn, which is held through
    // the recovery below.
    let Some(turn) = stage.slot().begin_load().await else {
        return DeviceSwitch::Superseded;
    };
    stage.announce(StageEvent::LoadingOnDevice {
        model: &model,
        device,
    });
    let error = match build(stage, &turn, &model, Some(device), shutdown.as_mut()).await {
        None => return DeviceSwitch::Cancelled,
        Some(Ok(built)) => {
            let actual = built.device();
            turn.install(built).await;
            stage.set_device(&model, device).await;
            info!("Moved {model} to {device} (running on {actual})");
            stage.announce(StageEvent::DeviceSwitched {
                model: &model,
                device: &actual,
                preferred: device,
            });
            return DeviceSwitch::Switched { device: actual };
        }
        Some(Err(error)) => error,
    };

    let shown = format!("{error:#}");
    warn!("Failed to move {model} to {device}: {shown}; loading it again on {fallback}");
    stage.announce(StageEvent::DeviceSwitchFailed {
        model: &model,
        device,
        error: &shown,
    });
    stage.announce(StageEvent::LoadingOnDevice {
        model: &model,
        device: fallback,
    });
    match build(stage, &turn, &model, Some(fallback), shutdown).await {
        None => DeviceSwitch::Cancelled,
        Some(Ok(built)) => {
            let actual = built.device();
            turn.install(built).await;
            warn!("Loaded {model} again on {fallback} (running on {actual})");
            stage.announce(StageEvent::DeviceSwitched {
                model: &model,
                device: &actual,
                preferred: fallback,
            });
            DeviceSwitch::Recovered {
                error,
                device: actual,
            }
        }
        Some(Err(recovery)) => {
            let shown = format!("{recovery:#}");
            warn!("Failed to load {model} again on {fallback}: {shown}");
            stage.announce(StageEvent::LoadFailed {
                model: &model,
                error: &shown,
            });
            drop(turn);
            DeviceSwitch::Failed { error, recovery }
        }
    }
}

/// Build `model` on `turn`, unless the daemon starts shutting down first:
/// `None`.
async fn build<S: Stage>(
    stage: &S,
    turn: &LoadTurn<'_, S::Model>,
    model: &ModelId,
    device: Option<&str>,
    shutdown: Pin<&mut impl Future<Output = ()>>,
) -> Option<anyhow::Result<S::Model>> {
    tokio::select! {
        biased;
        () = shutdown => {
            warn!("Stopped loading {model}: the daemon is shutting down");
            None
        }
        built = stage.instantiate(turn, model, device) => Some(built),
    }
}

/// Every stage a daemon runs, of every feature, for what is done to all of
/// them at once.
#[derive(Clone, Default)]
pub struct Stages(Vec<Arc<dyn AnyStage>>);

impl Stages {
    /// No stages yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// These stages and `stage`.
    #[must_use]
    pub fn with<S: Stage>(mut self, stage: S) -> Self {
        self.0.push(Arc::new(Erased(stage)));
        self
    }

    /// Record a use of every stage's model now: its idle time starts again.
    pub fn touch(&self) {
        for stage in &self.0 {
            stage.touch();
        }
    }

    /// Load each stage's selected model in the background, as a daemon
    /// starts. A stage whose model is unloaded on idle is left to the first
    /// request that needs it.
    pub async fn load_at_startup(&self) {
        let mut on_demand = 0;
        for stage in &self.0 {
            if stage.idle_after().await.is_some() {
                on_demand += 1;
                continue;
            }
            let stage = Arc::clone(stage);
            tokio::spawn(async move { stage.load_selected().await });
        }
        if on_demand > 0 {
            info!("Models are unloaded when idle: {on_demand} stage(s) load on first use");
        }
    }

    /// Load every stage's selected model that is not in memory, all at once,
    /// and wait for them. Each logs its own failure.
    pub async fn load_selected(&self) {
        futures_util::future::join_all(self.0.iter().map(|stage| stage.load_selected())).await;
    }

    /// Unload every stage's model that has gone unused for its idle time.
    pub async fn unload_idle(&self) {
        for stage in &self.0 {
            if let Some(after) = stage.idle_after().await {
                stage.unload_if_idle(after).await;
            }
        }
    }

    /// Unload idle models every [`CHECK_EVERY`] until `shutdown` completes.
    /// It reads the setting each time, so it runs whether or not idle unload
    /// is on.
    pub fn spawn_idle_unload(&self, shutdown: impl Future<Output = ()> + Send + 'static) {
        let stages = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CHECK_EVERY);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tokio::pin!(shutdown);
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    () = &mut shutdown => return,
                }
                stages.unload_idle().await;
            }
        });
    }

    /// Stop every stage's model as the daemon exits, so no backend outlives
    /// it.
    pub async fn shutdown(&self) {
        for stage in &self.0 {
            stage.shutdown().await;
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A [`Stage`] whatever its model, so [`Stages`] holds every feature's.
trait AnyStage: Send + Sync {
    fn touch(&self);
    fn idle_after(&self) -> BoxFuture<'_, Option<Duration>>;
    fn load_selected(&self) -> BoxFuture<'_, Load>;
    fn unload_if_idle(&self, after: Duration) -> BoxFuture<'_, bool>;
    fn shutdown(&self) -> BoxFuture<'_, bool>;
}

struct Erased<S>(S);

impl<S: Stage> AnyStage for Erased<S> {
    fn touch(&self) {
        self.0.slot().touch();
    }

    fn idle_after(&self) -> BoxFuture<'_, Option<Duration>> {
        Box::pin(self.0.idle_after())
    }

    fn load_selected(&self) -> BoxFuture<'_, Load> {
        Box::pin(self.0.load_selected())
    }

    fn unload_if_idle(&self, after: Duration) -> BoxFuture<'_, bool> {
        Box::pin(self.0.unload_if_idle(after))
    }

    fn shutdown(&self) -> BoxFuture<'_, bool> {
        Box::pin(self.0.shutdown())
    }
}

#[cfg(test)]
#[path = "stage_tests.rs"]
mod tests;
