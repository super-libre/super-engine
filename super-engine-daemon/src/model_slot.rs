// SPDX-License-Identifier: GPL-3.0-only
//! One model slot: the model a daemon holds for one purpose, and every load,
//! unload and use of it.
//!
//! A slot used to be a bare `RwLock<Option<_>>` beside a [`LoadGate`], with
//! each daemon adding its own idle clock, on-demand load and idle unload. Each
//! piece was right on its own and they raced where they met:
//!
//! - The gate was released when a load had its model, before the caller put
//!   it in the slot. A request arriving in between found the slot empty and
//!   loaded a second copy.
//! - Every request took a ticket, so a load on demand of the model already
//!   selected cancelled a model switch the user had queued.
//! - Each load emptied the slot before it queued. A load that finished while
//!   another waited put its model in, and the waiting one then loaded beside
//!   it and dropped it without stopping its backend.
//! - An unload found the slot empty during a load, did nothing, and the load
//!   then put the model the user had just unloaded back in.
//!
//! [`ModelSlot`] owns the whole sequence, so none of those can happen:
//!
//! - A load holds the gate from its turn until its model is in the slot
//!   ([`LoadTurn::install`]), and empties the slot only once it is its turn.
//! - A load on demand ([`ModelSlot::begin_load_if_empty`]) waits for every
//!   load and unload in flight, then loads only into a slot still empty, and
//!   never supersedes a request.
//! - An unload ([`ModelSlot::unload`]) is a request like a load: loads still
//!   waiting give up, and one already running finishes and is then unloaded.
//! - An idle unload ([`ModelSlot::unload_if_idle`]) holds the slot until its
//!   backend has stopped and it has said so, so the next load neither shares
//!   the memory nor announces itself first.

use crate::load_gate::LoadGate;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{
    Mutex, MutexGuard, Notify, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError,
};

/// What a [`ModelSlot`] holds.
pub trait SlotModel: Send + Sync + 'static {
    /// Stop the model's backend before it is dropped. A failure is the
    /// model's to log: the slot drops it either way.
    fn shutdown(&mut self) -> impl Future<Output = ()> + Send;
}

/// One model a daemon holds, with its loads, unloads and idle time.
pub struct ModelSlot<M> {
    model: RwLock<Option<M>>,
    gate: LoadGate,
    /// Loads and unloads asked for and not yet done. A load on demand waits
    /// for none to be left, so it never races one.
    in_flight: AtomicUsize,
    /// Signalled when `in_flight` drops to zero.
    settled: Notify,
    /// Held across a load on demand, so requests arriving together wait for
    /// one load.
    on_demand: Mutex<()>,
    /// Held by an idle unload from taking the model out to announcing it
    /// gone. Every load waits for it, as does [`Self::shutdown`].
    unloading: Mutex<()>,
    last_used: std::sync::Mutex<Instant>,
}

impl<M> Default for ModelSlot<M> {
    fn default() -> Self {
        Self {
            model: RwLock::new(None),
            gate: LoadGate::default(),
            in_flight: AtomicUsize::new(0),
            settled: Notify::new(),
            on_demand: Mutex::new(()),
            unloading: Mutex::new(()),
            last_used: std::sync::Mutex::new(Instant::now()),
        }
    }
}

impl<M> std::fmt::Debug for ModelSlot<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelSlot")
            .field("in_flight", &self.in_flight.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl<M: SlotModel> ModelSlot<M> {
    /// Read the model in the slot. Hold the guard for as long as the model is
    /// used: a load waits for it before taking the model out.
    pub async fn read(&self) -> RwLockReadGuard<'_, Option<M>> {
        self.model.read().await
    }

    /// [`Self::read`], without waiting.
    ///
    /// # Errors
    /// When a load or an unload is taking the model out right now.
    pub fn try_read(&self) -> Result<RwLockReadGuard<'_, Option<M>>, TryLockError> {
        self.model.try_read()
    }

    /// Use the model mutably, for a call that needs `&mut`. Held like
    /// [`Self::read`]: a load waits for it. The guard reaches the model but
    /// cannot take it out or put another in; only loads and unloads do that.
    pub async fn write(&self) -> ModelWriteGuard<'_, M> {
        ModelWriteGuard(self.model.write().await)
    }

    /// [`Self::write`], from a blocking thread.
    ///
    /// # Panics
    /// When called from an async context.
    pub fn blocking_write(&self) -> ModelWriteGuard<'_, M> {
        ModelWriteGuard(self.model.blocking_write())
    }

    /// Whether a model is in the slot.
    pub async fn is_loaded(&self) -> bool {
        self.model.read().await.is_some()
    }

    /// Record a use of the model, now.
    pub fn touch(&self) {
        *self.last() = Instant::now();
    }

    /// How long since the model was last used, or since it was loaded.
    #[must_use]
    pub fn idle_for(&self) -> Duration {
        self.last().elapsed()
    }

    /// Make the model look unused for `by` more. For tests.
    ///
    /// # Panics
    /// When the clock cannot go back that far.
    pub fn backdate(&self, by: Duration) {
        let mut last = self.last();
        *last = last
            .checked_sub(by)
            .expect("the clock predates the backdate");
    }

    fn last(&self) -> std::sync::MutexGuard<'_, Instant> {
        self.last_used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ask to load a model into the slot: a switch, a device change, a
    /// reload, a start-up load.
    ///
    /// Waits for its turn. A request asked for after this one, load or
    /// unload, makes it give up: `None`, and the slot is left to the newer
    /// one. On its turn the model in the slot, if any, is stopped and taken
    /// out, so two models never share the memory.
    ///
    /// Load the model while holding the [`LoadTurn`], then
    /// [`install`](LoadTurn::install) it. Dropping the turn instead leaves
    /// the slot empty: the load failed.
    pub async fn begin_load(&self) -> Option<LoadTurn<'_, M>> {
        let in_flight = InFlight::new(self);
        let ticket = self.gate.ticket();
        let gate = self.gate.enter(ticket).await?;
        drop(self.unloading.lock().await);
        self.empty().await;
        Some(LoadTurn {
            slot: self,
            _gate: gate,
            _in_flight: in_flight,
            _on_demand: None,
        })
    }

    /// Ask to load a model on demand: a request found the slot empty and
    /// needs a model.
    ///
    /// Waits for every load and unload in flight, so it never loads beside
    /// one or puts back a model one has just taken out. `None` when the slot
    /// is filled by then, or when a load or unload is asked for before this
    /// one's turn: that one decides what is in the slot. It never makes
    /// another request give up.
    ///
    /// Requests arriving together wait for one load: the first gets the turn
    /// and the rest find the slot filled.
    pub async fn begin_load_if_empty(&self) -> Option<LoadTurn<'_, M>> {
        let on_demand = self.on_demand.lock().await;
        self.settle().await;
        if self.model.read().await.is_some() {
            return None;
        }
        let in_flight = InFlight::new(self);
        let seen = self.gate.newest();
        let gate = self.gate.enter(seen).await?;
        if self.model.read().await.is_some() {
            return None;
        }
        drop(self.unloading.lock().await);
        Some(LoadTurn {
            slot: self,
            _gate: gate,
            _in_flight: in_flight,
            _on_demand: Some(on_demand),
        })
    }

    /// Ask to unload the model.
    ///
    /// A request like a load: loads still waiting give up, and a load already
    /// running finishes first and its model is the one unloaded. `None` when a
    /// load is asked for before this one's turn: it replaces the model anyway.
    ///
    /// The model is stopped and taken out before this returns. Hold the
    /// [`Unloaded`] while recording that it is off (the caller's config, its
    /// announcement): no load, on demand or not, starts until it is dropped.
    pub async fn unload(&self) -> Option<Unloaded<'_, M>> {
        let in_flight = InFlight::new(self);
        let ticket = self.gate.ticket();
        let gate = self.gate.enter(ticket).await?;
        drop(self.unloading.lock().await);
        let model = self.take_and_stop().await;
        Some(Unloaded {
            model,
            _gate: gate,
            _in_flight: in_flight,
        })
    }

    /// Unload the model if it has gone unused for `after`. Returns whether it
    /// did.
    ///
    /// Left alone while a load or an unload is in flight, which decides what
    /// is in the slot, and while the model is being used through
    /// [`Self::read`] or [`Self::write`], which restarts its idle time. The
    /// caller checks its own notion of "in use" (a recording, an utterance)
    /// first.
    ///
    /// `announce` runs once the backend has stopped, with the model it ran.
    /// Every load waits for it, so the next model's announcement never comes
    /// first.
    pub async fn unload_if_idle(&self, after: Duration, announce: impl FnOnce(&M)) -> bool {
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            return false;
        }
        let _unloading = self.unloading.lock().await;
        let taken = {
            let Ok(mut slot) = self.model.try_write() else {
                self.touch();
                return false;
            };
            if self.idle_for() < after {
                return false;
            }
            slot.take()
        };
        let Some(mut model) = taken else {
            return false;
        };
        model.shutdown().await;
        announce(&model);
        true
    }

    /// Stop and take out the model as the daemon exits.
    ///
    /// Waits for an idle unload still stopping its backend, which has the
    /// model out of the slot, but not for a load: that can take minutes.
    pub async fn shutdown(&self) -> Option<M> {
        let _unloading = self.unloading.lock().await;
        self.take_and_stop().await
    }

    async fn empty(&self) {
        drop(self.take_and_stop().await);
    }

    /// Take the model out, then stop it outside the lock: a backend can take
    /// seconds to free its memory, and every reader would wait that long.
    async fn take_and_stop(&self) -> Option<M> {
        let mut taken = self.model.write().await.take();
        if let Some(model) = taken.as_mut() {
            model.shutdown().await;
        }
        taken
    }

    /// Wait until no load or unload is in flight.
    async fn settle(&self) {
        loop {
            let notified = self.settled.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_flight.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// Mutable use of the model in a slot. See [`ModelSlot::write`].
pub struct ModelWriteGuard<'a, M>(RwLockWriteGuard<'a, Option<M>>);

impl<M> ModelWriteGuard<'_, M> {
    /// The model, if one is in the slot.
    #[must_use]
    pub fn get(&self) -> Option<&M> {
        self.0.as_ref()
    }

    /// The model, mutably, if one is in the slot.
    pub fn get_mut(&mut self) -> Option<&mut M> {
        self.0.as_mut()
    }
}

/// A load's turn at the slot. See [`ModelSlot::begin_load`].
#[must_use = "a load that drops its turn leaves the slot empty"]
pub struct LoadTurn<'a, M: SlotModel> {
    slot: &'a ModelSlot<M>,
    _gate: MutexGuard<'a, ()>,
    _in_flight: InFlight<'a, M>,
    _on_demand: Option<MutexGuard<'a, ()>>,
}

impl<M: SlotModel> LoadTurn<'_, M> {
    /// Put the loaded model in the slot, ending the turn. Its idle time
    /// starts now.
    pub async fn install(self, model: M) {
        let previous = {
            let mut slot = self.slot.model.write().await;
            self.slot.touch();
            slot.replace(model)
        };
        // Emptied on this turn and held since, so nothing is here. Should
        // that ever change, the model is still stopped rather than dropped.
        if let Some(mut previous) = previous {
            previous.shutdown().await;
        }
    }
}

/// An unload's result, holding the slot. See [`ModelSlot::unload`].
#[must_use = "dropping it lets loads start before the unload is recorded"]
pub struct Unloaded<'a, M: SlotModel> {
    /// The model taken out, already stopped. `None` when the slot was empty.
    pub model: Option<M>,
    _gate: MutexGuard<'a, ()>,
    _in_flight: InFlight<'a, M>,
}

/// A load or unload counted in flight until dropped.
struct InFlight<'a, M> {
    slot: &'a ModelSlot<M>,
}

impl<'a, M> InFlight<'a, M> {
    fn new(slot: &'a ModelSlot<M>) -> Self {
        slot.in_flight.fetch_add(1, Ordering::SeqCst);
        Self { slot }
    }
}

impl<M> Drop for InFlight<'_, M> {
    fn drop(&mut self) {
        if self.slot.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.slot.settled.notify_waiters();
        }
    }
}

#[cfg(test)]
#[path = "model_slot_tests.rs"]
mod tests;
