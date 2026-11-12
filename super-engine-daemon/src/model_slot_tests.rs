// SPDX-License-Identifier: GPL-3.0-only
//! Each test is one of the races [`ModelSlot`] exists to close, staged the way
//! it happened: a load running when another request arrives.

use super::{ModelSlot, SlotModel};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

/// A model that counts its shutdowns. With `hold`, its shutdown waits to be
/// let go, the way a backend freeing GPU memory takes its time.
#[derive(Debug)]
struct Fake {
    id: u32,
    stopped: Arc<AtomicUsize>,
    hold: Option<Arc<Notify>>,
}

impl Fake {
    fn new(id: u32) -> Self {
        Self {
            id,
            stopped: Arc::default(),
            hold: None,
        }
    }
}

impl SlotModel for Fake {
    async fn shutdown(&mut self) {
        if let Some(hold) = &self.hold {
            hold.notified().await;
        }
        self.stopped.fetch_add(1, Ordering::SeqCst);
    }
}

async fn loaded(slot: &ModelSlot<Fake>) -> Option<u32> {
    slot.read().await.as_ref().map(|m| m.id)
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

fn in_flight(slot: &ModelSlot<Fake>) -> usize {
    slot.in_flight.load(Ordering::SeqCst)
}

/// A load takes the model in the slot out and stops it on its turn, and
/// installs its own.
#[tokio::test]
async fn a_load_stops_the_model_it_replaces() {
    let slot = ModelSlot::default();
    let first = Fake::new(1);
    let stopped = Arc::clone(&first.stopped);
    slot.begin_load().await.unwrap().install(first).await;

    let turn = slot.begin_load().await.unwrap();
    assert_eq!(stopped.load(Ordering::SeqCst), 1, "replaced without a stop");
    assert_eq!(loaded(&slot).await, None, "two models in the slot at once");
    turn.install(Fake::new(2)).await;

    assert_eq!(loaded(&slot).await, Some(2));
}

/// Of the loads waiting while one runs, only the newest goes ahead.
#[tokio::test]
async fn waiting_loads_give_up_for_a_newer_one() {
    let slot = Arc::new(ModelSlot::default());
    let running = slot.begin_load().await.unwrap();

    let older = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.begin_load().await.map(|turn| drop(turn)).is_some() }
    });
    until(|| in_flight(&slot) == 2).await;
    let newer = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.begin_load().await.map(|turn| drop(turn)).is_some() }
    });
    until(|| in_flight(&slot) == 3).await;

    running.install(Fake::new(1)).await;
    assert!(!older.await.unwrap(), "a superseded load ran");
    assert!(newer.await.unwrap(), "the newest load did not run");
}

/// A request that finds the slot empty while a load runs waits for it and
/// uses its model, rather than loading a second copy once the gate opens.
#[tokio::test]
async fn a_load_on_demand_waits_for_a_load_in_flight() {
    let slot = Arc::new(ModelSlot::default());
    let running = slot.begin_load().await.unwrap();

    let on_demand = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.begin_load_if_empty().await.is_some() }
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!on_demand.is_finished(), "went ahead of the load in flight");

    running.install(Fake::new(1)).await;
    assert!(!on_demand.await.unwrap(), "loaded a second copy");
    assert_eq!(loaded(&slot).await, Some(1));
}

/// A load on demand never cancels a load someone asked for: here a model
/// switch queued behind a load that then fails.
#[tokio::test]
async fn a_load_on_demand_never_cancels_a_queued_load() {
    let slot = Arc::new(ModelSlot::default());
    let running = slot.begin_load().await.unwrap();
    let switch = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move {
            match slot.begin_load().await {
                Some(turn) => {
                    turn.install(Fake::new(2)).await;
                    true
                }
                None => false,
            }
        }
    });
    until(|| in_flight(&slot) == 2).await;
    let on_demand = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.begin_load_if_empty().await.is_some() }
    });
    tokio::task::yield_now().await;

    drop(running);
    assert!(switch.await.unwrap(), "the queued switch was cancelled");
    assert!(!on_demand.await.unwrap(), "loaded over the switch");
    assert_eq!(loaded(&slot).await, Some(2));
}

/// Requests arriving together while the slot is empty share one load.
#[tokio::test]
async fn loads_on_demand_arriving_together_load_once() {
    let slot = Arc::new(ModelSlot::default());
    let first = slot.begin_load_if_empty().await.unwrap();
    let second = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.begin_load_if_empty().await.is_some() }
    });
    tokio::task::yield_now().await;

    first.install(Fake::new(1)).await;
    assert!(!second.await.unwrap(), "loaded twice");
}

/// An unload during a load waits for it and unloads what it loaded, instead
/// of finding the slot empty and letting the load put the model back.
#[tokio::test]
async fn an_unload_waits_for_a_running_load_and_unloads_its_model() {
    let slot = Arc::new(ModelSlot::default());
    let running = slot.begin_load().await.unwrap();
    let unload = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.unload().await.map(|u| u.model.map(|m: Fake| m.id)) }
    });
    until(|| in_flight(&slot) == 2).await;

    let model = Fake::new(1);
    let stopped = Arc::clone(&model.stopped);
    running.install(model).await;

    assert_eq!(unload.await.unwrap(), Some(Some(1)));
    assert_eq!(stopped.load(Ordering::SeqCst), 1, "unloaded without a stop");
    assert_eq!(loaded(&slot).await, None);
}

/// An unload is newer than the loads waiting before it, so they give up.
#[tokio::test]
async fn an_unload_makes_waiting_loads_give_up() {
    let slot = Arc::new(ModelSlot::default());
    let running = slot.begin_load().await.unwrap();
    let waiting = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.begin_load().await.map(|turn| drop(turn)).is_some() }
    });
    until(|| in_flight(&slot) == 2).await;
    let unload = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.unload().await.is_some() }
    });
    until(|| in_flight(&slot) == 3).await;

    drop(running);
    assert!(!waiting.await.unwrap(), "a load the unload superseded ran");
    assert!(unload.await.unwrap());
}

/// No load on demand starts while an unload is being recorded, so it cannot
/// read the selection the unload is about to switch off.
#[tokio::test]
async fn no_load_on_demand_starts_while_an_unload_is_held() {
    let slot = Arc::new(ModelSlot::<Fake>::default());
    let unloaded = slot.unload().await.unwrap();
    let on_demand = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.begin_load_if_empty().await.is_some() }
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!on_demand.is_finished(), "started during the unload");

    drop(unloaded);
    assert!(on_demand.await.unwrap());
}

/// An idle unload takes out and stops a model unused for long enough, and
/// announces it with the model it ran.
#[tokio::test]
async fn an_idle_unload_stops_a_model_unused_for_long_enough() {
    let slot = ModelSlot::default();
    let model = Fake::new(1);
    let stopped = Arc::clone(&model.stopped);
    slot.begin_load().await.unwrap().install(model).await;

    assert!(!slot.unload_if_idle(Duration::from_secs(30), |_| {}).await);
    slot.backdate(Duration::from_secs(60));
    let mut announced = None;
    assert!(
        slot.unload_if_idle(Duration::from_secs(30), |m| announced = Some(m.id))
            .await
    );

    assert_eq!(announced, Some(1));
    assert_eq!(stopped.load(Ordering::SeqCst), 1);
    assert_eq!(loaded(&slot).await, None);
}

/// A model being read is in use: left alone, and its idle time restarts.
#[tokio::test]
async fn an_idle_unload_leaves_a_model_being_read() {
    let slot = ModelSlot::default();
    slot.begin_load().await.unwrap().install(Fake::new(1)).await;
    slot.backdate(Duration::from_secs(60));

    let reading = slot.read().await;
    assert!(!slot.unload_if_idle(Duration::from_secs(30), |_| {}).await);
    drop(reading);

    assert!(slot.idle_for() < Duration::from_secs(30));
    assert_eq!(loaded(&slot).await, Some(1));
}

/// A model starts a fresh idle time when installed, however long the slot sat
/// unused before.
#[tokio::test]
async fn an_installed_model_starts_a_fresh_idle_time() {
    let slot = ModelSlot::default();
    slot.backdate(Duration::from_secs(600));
    slot.begin_load().await.unwrap().install(Fake::new(1)).await;

    assert!(!slot.unload_if_idle(Duration::from_secs(30), |_| {}).await);
}

/// A load waits for an idle unload to stop its backend and announce it, so
/// two models never share the memory and the announcements stay in order.
#[tokio::test]
async fn a_load_waits_for_an_idle_unload_to_finish() {
    let slot = Arc::new(ModelSlot::default());
    let hold = Arc::new(Notify::new());
    let mut model = Fake::new(1);
    model.hold = Some(Arc::clone(&hold));
    slot.begin_load().await.unwrap().install(model).await;
    slot.backdate(Duration::from_secs(60));

    let announced = Arc::new(AtomicUsize::new(0));
    let unload = tokio::spawn({
        let slot = Arc::clone(&slot);
        let announced = Arc::clone(&announced);
        async move {
            slot.unload_if_idle(Duration::from_secs(30), |_| {
                announced.fetch_add(1, Ordering::SeqCst);
            })
            .await
        }
    });
    tokio::task::yield_now().await;
    let load = tokio::spawn({
        let slot = Arc::clone(&slot);
        let announced = Arc::clone(&announced);
        async move {
            let turn = slot.begin_load().await.unwrap();
            let seen = announced.load(Ordering::SeqCst);
            turn.install(Fake::new(2)).await;
            seen
        }
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        !load.is_finished(),
        "loaded while the old model was stopping"
    );

    hold.notify_one();
    assert!(unload.await.unwrap());
    assert_eq!(
        load.await.unwrap(),
        1,
        "the load went ahead of the announcement"
    );
    assert_eq!(loaded(&slot).await, Some(2));
}

/// Shutdown waits for an idle unload still stopping its backend: the model is
/// out of the slot by then, and exiting would leave the backend running.
#[tokio::test]
async fn shutdown_waits_for_an_idle_unload() {
    let slot = Arc::new(ModelSlot::default());
    let hold = Arc::new(Notify::new());
    let mut model = Fake::new(1);
    model.hold = Some(Arc::clone(&hold));
    let stopped = Arc::clone(&model.stopped);
    slot.begin_load().await.unwrap().install(model).await;
    slot.backdate(Duration::from_secs(60));

    let unload = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.unload_if_idle(Duration::from_secs(30), |_| {}).await }
    });
    tokio::task::yield_now().await;
    let shutdown = tokio::spawn({
        let slot = Arc::clone(&slot);
        async move { slot.shutdown().await.is_none() }
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        !shutdown.is_finished(),
        "exited while the backend was stopping"
    );

    hold.notify_one();
    assert!(unload.await.unwrap());
    assert!(shutdown.await.unwrap());
    assert_eq!(stopped.load(Ordering::SeqCst), 1);
}

/// A model in use through the write guard is in use too, and the guard reaches
/// the model without being able to take it out.
#[tokio::test]
async fn an_idle_unload_leaves_a_model_being_written() {
    let slot = ModelSlot::default();
    slot.begin_load().await.unwrap().install(Fake::new(1)).await;
    slot.backdate(Duration::from_secs(60));

    let mut writing = slot.write().await;
    writing.get_mut().expect("the model").id = 2;
    assert!(!slot.unload_if_idle(Duration::from_secs(30), |_| {}).await);
    drop(writing);

    assert_eq!(loaded(&slot).await, Some(2));
}
