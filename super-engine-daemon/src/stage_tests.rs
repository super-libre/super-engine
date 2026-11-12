// SPDX-License-Identifier: GPL-3.0-only
//! Each test is one thing every stage does with its model, run on a fake
//! stage that records what it was asked to do and what it told its clients.

use super::{DeviceSwitch, Load, ModelId, Stage, StageEvent, StageExt, StageModel, Stages, Unload};
use crate::model_slot::{LoadTurn, ModelSlot, SlotModel};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Semaphore, watch};

#[derive(Debug)]
struct Model {
    id: ModelId,
    device: String,
    stopped: Arc<AtomicUsize>,
}

impl SlotModel for Model {
    async fn shutdown(&mut self) {
        self.stopped.fetch_add(1, Ordering::SeqCst);
    }
}

impl StageModel for Model {
    fn id(&self) -> ModelId {
        self.id.clone()
    }

    fn device(&self) -> String {
        self.device.clone()
    }
}

/// A stage that loads models in memory, and records what it was asked.
#[derive(Clone)]
struct Fake(Arc<State>);

struct State {
    slot: ModelSlot<Model>,
    selected: Mutex<Option<ModelId>>,
    on: AtomicBool,
    idle_after: Mutex<Option<Duration>>,
    busy: AtomicBool,
    events: Mutex<Vec<String>>,
    /// Each model's own framework, by name.
    devices: Mutex<HashMap<String, String>>,
    /// Model names, or `name@device`, whose build fails.
    failing: Mutex<HashSet<String>>,
    /// When set, each build waits for a permit.
    gate: Mutex<Option<Arc<Semaphore>>>,
    builds: AtomicUsize,
    stopped: Arc<AtomicUsize>,
    shutdown: watch::Sender<bool>,
}

fn id(name: &str) -> ModelId {
    ModelId::new(name, "github.com/x/fake")
}

impl Fake {
    /// A stage switched on with `name` selected, nothing loaded, and models
    /// kept loaded.
    fn new(name: &str) -> Self {
        Self(Arc::new(State {
            slot: ModelSlot::default(),
            selected: Mutex::new(Some(id(name))),
            on: AtomicBool::new(true),
            idle_after: Mutex::new(None),
            busy: AtomicBool::new(false),
            events: Mutex::default(),
            devices: Mutex::default(),
            failing: Mutex::default(),
            gate: Mutex::new(None),
            builds: AtomicUsize::new(0),
            stopped: Arc::default(),
            shutdown: watch::channel(false).0,
        }))
    }

    /// The same stage, with models unloaded after 30 s idle.
    fn unloaded_on_idle(self) -> Self {
        *self.0.idle_after.lock().unwrap() = Some(Duration::from_secs(30));
        self
    }

    /// Make building `what` (a name, or `name@device`) fail.
    fn fail(&self, what: &str) {
        self.0.failing.lock().unwrap().insert(what.to_string());
    }

    /// Make each build wait for a permit from what this returns.
    fn hold(&self) -> Arc<Semaphore> {
        let gate = Arc::new(Semaphore::new(0));
        *self.0.gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    /// Put `name`, running on `device`, in the slot, without a word to
    /// clients.
    async fn put(&self, name: &str, device: &str) {
        let turn = self.0.slot.begin_load().await.unwrap();
        turn.install(Model {
            id: id(name),
            device: device.to_string(),
            stopped: Arc::clone(&self.0.stopped),
        })
        .await;
    }

    /// The events so far, which are then forgotten.
    fn events(&self) -> Vec<String> {
        std::mem::take(&mut self.0.events.lock().unwrap())
    }

    fn saw(&self, event: &str) -> bool {
        self.0.events.lock().unwrap().iter().any(|e| e == event)
    }

    /// The name of the model loaded, and the framework it runs on.
    async fn loaded(&self) -> Option<(String, String)> {
        self.0
            .slot
            .read()
            .await
            .as_ref()
            .map(|m| (m.id.name.clone(), m.device.clone()))
    }

    fn selection(&self) -> Option<String> {
        self.0
            .selected
            .lock()
            .unwrap()
            .as_ref()
            .map(|m| m.name.clone())
    }

    fn device_of(&self, name: &str) -> Option<String> {
        self.0.devices.lock().unwrap().get(name).cloned()
    }

    fn is_on(&self) -> bool {
        self.0.on.load(Ordering::SeqCst)
    }

    fn builds(&self) -> usize {
        self.0.builds.load(Ordering::SeqCst)
    }

    fn stopped(&self) -> usize {
        self.0.stopped.load(Ordering::SeqCst)
    }

    fn shut_down(&self) {
        self.0.shutdown.send_replace(true);
    }
}

impl Stage for Fake {
    type Model = Model;

    fn slot(&self) -> &ModelSlot<Model> {
        &self.0.slot
    }

    async fn selected(&self) -> Result<ModelId, Option<String>> {
        if !self.is_on() {
            return Err(Some("switched off".to_string()));
        }
        self.0.selected.lock().unwrap().clone().ok_or(None)
    }

    async fn instantiate(
        &self,
        _turn: &LoadTurn<'_, Model>,
        model: &ModelId,
        device: Option<&str>,
    ) -> anyhow::Result<Model> {
        let gate = self.0.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.acquire().await?.forget();
        }
        self.0.builds.fetch_add(1, Ordering::SeqCst);
        let device = device
            .map(str::to_string)
            .or_else(|| self.device_of(&model.name))
            .unwrap_or_else(|| "cpu".to_string());
        let fails = {
            let failing = self.0.failing.lock().unwrap();
            failing.contains(&model.name) || failing.contains(&format!("{model}@{device}"))
        };
        if fails {
            anyhow::bail!("{model} cannot run on {device}");
        }
        Ok(Model {
            id: model.clone(),
            device,
            stopped: Arc::clone(&self.0.stopped),
        })
    }

    async fn idle_after(&self) -> Option<Duration> {
        *self.0.idle_after.lock().unwrap()
    }

    fn in_use(&self) -> bool {
        self.0.busy.load(Ordering::SeqCst)
    }

    fn announce(&self, event: StageEvent<'_>) {
        let said = match event {
            StageEvent::Loading { model } => format!("loading {model}"),
            StageEvent::Loaded { model, device } => format!("loaded {model} on {device}"),
            StageEvent::Unloaded => "unloaded".to_string(),
            StageEvent::LoadFailed { model, .. } => format!("{model} failed"),
            StageEvent::SwitchingDevice { model, from, to } => {
                format!("moving {model} from {from} to {to}")
            }
            StageEvent::LoadingOnDevice { model, device } => format!("loading {model} on {device}"),
            StageEvent::DeviceSwitchFailed { model, device, .. } => {
                format!("{model} failed on {device}")
            }
            StageEvent::DeviceSwitched {
                model,
                device,
                preferred,
            } => format!("{model} runs on {device} for {preferred}"),
        };
        self.0.events.lock().unwrap().push(said);
    }

    async fn select(&self, model: &ModelId) {
        *self.0.selected.lock().unwrap() = Some(model.clone());
        self.0.on.store(true, Ordering::SeqCst);
    }

    async fn switch_off(&self) -> bool {
        self.0.on.swap(false, Ordering::SeqCst)
    }

    async fn set_device(&self, model: &ModelId, device: &str) {
        self.0
            .devices
            .lock()
            .unwrap()
            .insert(model.name.clone(), device.to_string());
    }

    fn shutdown_signal(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut down = self.0.shutdown.subscribe();
        async move {
            let _ = down.wait_for(|down| *down).await;
        }
    }
}

/// Let other tasks run until `done` holds. The tests run on one thread, so a
/// spawned task moves only when the test yields.
async fn until(done: impl Fn() -> bool) {
    for _ in 0..1000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("never happened");
}

/// A request loads the selected model when models are unloaded on idle, and
/// says so.
#[tokio::test]
async fn a_request_loads_the_selected_model_when_models_unload_on_idle() {
    let stage = Fake::new("a").unloaded_on_idle();

    assert_eq!(stage.ensure_loaded().await, Ok(()));

    assert_eq!(stage.loaded().await, Some(("a".into(), "cpu".into())));
    assert_eq!(stage.events(), ["loading a", "loaded a on cpu"]);
}

/// With models kept loaded, a request finding none loads nothing: the model
/// was unloaded on purpose, or failed at startup.
#[tokio::test]
async fn a_request_loads_nothing_when_models_stay_loaded() {
    let stage = Fake::new("a");

    assert_eq!(stage.ensure_loaded().await, Ok(()));

    assert_eq!(stage.loaded().await, None);
    assert_eq!(stage.builds(), 0);
}

/// A load that fails says which model and why, to the request and to
/// clients, and leaves the stage empty.
#[tokio::test]
async fn a_failed_load_says_which_model_and_why() {
    let stage = Fake::new("a").unloaded_on_idle();
    stage.fail("a");

    let loaded = stage.ensure_loaded().await;

    assert_eq!(
        loaded,
        Err("a did not load: a cannot run on cpu".to_string())
    );
    assert_eq!(stage.events(), ["loading a", "a failed"]);
    assert_eq!(stage.loaded().await, None);
}

/// A request dropped while its load runs (its client gave up) does not stop
/// the load: the model is there for the next request.
#[tokio::test]
async fn a_load_outlives_its_request() {
    let stage = Fake::new("a").unloaded_on_idle();
    let gate = stage.hold();
    let request = tokio::spawn({
        let stage = stage.clone();
        async move { stage.ensure_loaded().await }
    });
    until(|| stage.saw("loading a")).await;

    request.abort();
    gate.add_permits(1);
    until(|| stage.saw("loaded a on cpu")).await;

    assert_eq!(stage.loaded().await, Some(("a".into(), "cpu".into())));
}

/// Requests arriving while the model loads wait for that load rather than
/// start their own.
#[tokio::test]
async fn requests_arriving_together_load_once() {
    let stage = Fake::new("a").unloaded_on_idle();
    let gate = stage.hold();
    let requests: Vec<_> = (0..3)
        .map(|_| {
            let stage = stage.clone();
            tokio::spawn(async move { stage.ensure_loaded().await })
        })
        .collect();
    until(|| stage.saw("loading a")).await;

    gate.add_permits(3);
    for request in requests {
        assert_eq!(request.await.unwrap(), Ok(()));
    }

    assert_eq!(stage.builds(), 1);
}

/// A switch records the choice before it loads, so a model that fails to
/// load stays selected rather than the one it replaced.
#[tokio::test]
async fn a_switch_records_the_choice_before_its_load() {
    let stage = Fake::new("a");
    stage.put("a", "cpu").await;
    stage.fail("b");

    let switched = stage.switch_to(id("b")).await;

    assert!(matches!(switched, Load::Failed { model, .. } if model == id("b")));
    assert_eq!(stage.selection().as_deref(), Some("b"));
    assert_eq!(stage.loaded().await, None);
    assert_eq!(stage.events(), ["loading b", "b failed"]);
}

/// A switch stops the model it replaces before it builds its own.
#[tokio::test]
async fn a_switch_replaces_the_model_and_stops_it() {
    let stage = Fake::new("a");
    stage.put("a", "cpu").await;

    let switched = stage.switch_to(id("b")).await;

    assert!(matches!(switched, Load::Loaded { model, .. } if model == id("b")));
    assert_eq!(stage.stopped(), 1);
    assert_eq!(stage.loaded().await, Some(("b".into(), "cpu".into())));
}

/// Asking for the model already loaded leaves it alone.
#[tokio::test]
async fn a_switch_to_the_loaded_model_changes_nothing() {
    let stage = Fake::new("a");
    stage.put("a", "cpu").await;

    assert!(matches!(stage.switch_to(id("a")).await, Load::Unchanged));

    assert_eq!(stage.builds(), 0);
    assert!(stage.events().is_empty());
}

/// A reload builds the loaded model again, where its setting puts it, and
/// does nothing with no model loaded.
#[tokio::test]
async fn a_reload_builds_the_loaded_model_again() {
    let stage = Fake::new("a");
    assert!(matches!(stage.reload().await, Load::Unchanged));
    stage.put("a", "cpu").await;
    stage.set_device(&id("a"), "cuda").await;

    let reloaded = stage.reload().await;

    assert!(matches!(reloaded, Load::Loaded { device, .. } if device == "cuda"));
    assert_eq!(stage.stopped(), 1);
    assert_eq!(stage.builds(), 1);
}

/// A device switch records the device once the model runs there.
#[tokio::test]
async fn a_device_switch_records_the_device_once_loaded_there() {
    let stage = Fake::new("a");
    stage.put("a", "cpu").await;

    let switched = stage
        .switch_device(id("a"), "cuda".into(), "cpu".into())
        .await;

    assert!(matches!(switched, DeviceSwitch::Switched { device } if device == "cuda"));
    assert_eq!(stage.device_of("a").as_deref(), Some("cuda"));
    assert_eq!(
        stage.events(),
        [
            "moving a from cpu to cuda",
            "loading a on cuda",
            "a runs on cuda for cuda"
        ]
    );
}

/// A device switch that fails loads the model again on its setting, and
/// leaves the setting as it was.
#[tokio::test]
async fn a_failed_device_switch_loads_the_model_again() {
    let stage = Fake::new("a");
    stage.put("a", "cpu").await;
    stage.fail("a@cuda");

    let switched = stage
        .switch_device(id("a"), "cuda".into(), "cpu".into())
        .await;

    assert!(matches!(switched, DeviceSwitch::Recovered { device, .. } if device == "cpu"));
    assert_eq!(stage.device_of("a"), None);
    assert_eq!(stage.loaded().await, Some(("a".into(), "cpu".into())));
    assert_eq!(
        stage.events(),
        [
            "moving a from cpu to cuda",
            "loading a on cuda",
            "a failed on cuda",
            "loading a on cpu",
            "a runs on cpu for cpu"
        ]
    );
}

/// A device switch whose recovery fails too leaves the stage empty, and says
/// so.
#[tokio::test]
async fn a_device_switch_that_cannot_recover_says_the_stage_is_empty() {
    let stage = Fake::new("a");
    stage.put("a", "cpu").await;
    stage.fail("a");

    let switched = stage
        .switch_device(id("a"), "cuda".into(), "cpu".into())
        .await;

    assert!(matches!(switched, DeviceSwitch::Failed { .. }));
    assert_eq!(stage.loaded().await, None);
    assert_eq!(stage.events().last().map(String::as_str), Some("a failed"));
}

/// A device for a model that is not loaded is only recorded, for its next
/// load.
#[tokio::test]
async fn a_device_switch_of_a_model_not_loaded_only_records_it() {
    let stage = Fake::new("a");

    let switched = stage
        .switch_device(id("a"), "cuda".into(), "cpu".into())
        .await;

    assert!(matches!(switched, DeviceSwitch::Recorded));
    assert_eq!(stage.device_of("a").as_deref(), Some("cuda"));
    assert_eq!(stage.builds(), 0);
}

/// An unload switches the stage off, so nothing loads the model again on
/// demand, and says the stage is empty.
#[tokio::test]
async fn an_unload_switches_the_stage_off() {
    let stage = Fake::new("a").unloaded_on_idle();
    stage.put("a", "cpu").await;

    let unloaded = stage.unload().await;

    assert!(matches!(unloaded, Unload::Unloaded { model: Some(m) } if m == id("a")));
    assert!(!stage.is_on());
    assert_eq!(stage.events(), ["unloaded"]);
    assert_eq!(stage.ensure_loaded().await, Ok(()));
    assert_eq!(stage.loaded().await, None);
}

/// A stage switched on with no model in memory (unloaded for being idle) is
/// switched off too. Once off, unloading again does nothing.
#[tokio::test]
async fn an_unload_switches_off_a_stage_with_no_model_in_memory() {
    let stage = Fake::new("a").unloaded_on_idle();

    assert!(matches!(
        stage.unload().await,
        Unload::Unloaded { model: None }
    ));
    assert!(!stage.is_on());
    assert_eq!(stage.events(), ["unloaded"]);

    assert!(matches!(stage.unload().await, Unload::NothingToUnload));
    assert!(stage.events().is_empty());
}

/// An unload during a load waits for it and unloads what it loaded, rather
/// than finding the slot empty and leaving the load to fill it.
#[tokio::test]
async fn an_unload_during_a_load_unloads_what_it_loaded() {
    let stage = Fake::new("a");
    let gate = stage.hold();
    let load = tokio::spawn({
        let stage = stage.clone();
        async move { stage.load_selected().await }
    });
    until(|| stage.saw("loading a")).await;
    let unload = tokio::spawn({
        let stage = stage.clone();
        async move { stage.unload().await }
    });
    tokio::task::yield_now().await;
    assert!(!unload.is_finished());

    gate.add_permits(1);
    assert!(matches!(load.await.unwrap(), Load::Loaded { .. }));
    let unloaded = unload.await.unwrap();

    assert!(matches!(unloaded, Unload::Unloaded { model: Some(_) }));
    assert_eq!(stage.loaded().await, None);
    assert!(!stage.is_on());
}

/// A model in use stays loaded however long it has been, and its idle time
/// starts again when the use ends.
#[tokio::test]
async fn an_idle_unload_leaves_a_model_in_use() {
    let after = Duration::from_secs(30);
    let stage = Fake::new("a");
    stage.put("a", "cpu").await;
    stage.slot().backdate(Duration::from_secs(60));

    stage.0.busy.store(true, Ordering::SeqCst);
    assert!(!stage.unload_if_idle(after).await);
    stage.0.busy.store(false, Ordering::SeqCst);
    assert!(!stage.unload_if_idle(after).await);

    stage.slot().backdate(Duration::from_secs(60));
    assert!(stage.unload_if_idle(after).await);
    assert!(stage.is_on(), "an idle unload keeps the stage on");
    assert_eq!(stage.events(), ["unloaded"]);
}

/// A load gives up when the daemon starts shutting down, rather than keep the
/// exit waiting on a model nobody will use.
#[tokio::test]
async fn a_shutdown_stops_a_load() {
    let stage = Fake::new("a");
    let _gate = stage.hold();
    let load = tokio::spawn({
        let stage = stage.clone();
        async move { stage.load_selected().await }
    });
    until(|| stage.saw("loading a")).await;

    stage.shut_down();

    assert!(matches!(load.await.unwrap(), Load::Cancelled));
    assert_eq!(stage.loaded().await, None);
}

/// A start loads every stage's model, except a stage whose model is unloaded
/// on idle: the first request that needs it loads it.
#[tokio::test]
async fn a_start_loads_every_stage_not_unloaded_on_idle() {
    let kept = Fake::new("a");
    let on_demand = Fake::new("b").unloaded_on_idle();
    let stages = Stages::new().with(kept.clone()).with(on_demand.clone());

    stages.load_at_startup().await;
    until(|| kept.saw("loaded a on cpu")).await;

    assert_eq!(on_demand.builds(), 0);
}

/// One idle pass unloads every stage gone idle, of whatever kind; loading
/// the selection brings them all back, and a shutdown stops them all.
#[tokio::test]
async fn stages_are_unloaded_loaded_and_stopped_together() {
    let first = Fake::new("a").unloaded_on_idle();
    let second = Fake::new("b").unloaded_on_idle();
    let stages = Stages::new().with(first.clone()).with(second.clone());
    for (stage, name) in [(&first, "a"), (&second, "b")] {
        stage.put(name, "cpu").await;
        stage.slot().backdate(Duration::from_secs(60));
    }

    stages.unload_idle().await;
    assert_eq!(first.loaded().await, None);
    assert_eq!(second.loaded().await, None);

    stages.load_selected().await;
    assert!(first.loaded().await.is_some());
    assert!(second.loaded().await.is_some());

    stages.shutdown().await;
    assert_eq!(first.loaded().await, None);
    assert_eq!(second.loaded().await, None);
}
