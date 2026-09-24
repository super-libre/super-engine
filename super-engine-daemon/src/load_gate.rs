// SPDX-License-Identifier: GPL-3.0-only
//! One model load at a time, and the newest request wins.

/// Serializes model loading, and lets a superseded load give up before it
/// starts.
///
/// Loading is the one operation in a daemon that takes minutes rather than
/// milliseconds — spawning a sandboxed backend, mapping weights onto a device,
/// compiling and tuning kernels — and every path that does it releases the
/// model slot first. Two requests could therefore both find the slot empty and
/// both proceed. That is not hypothetical: a daemon's startup auto-load and a
/// user picking a different model in the settings app ran at the same time, two
/// multi-gigabyte models sat on one GPU while both compiled kernels into the
/// same cache, and the one that lost simply stopped, with nothing in the log to
/// say why.
///
/// A plain mutex would fix the overlap and keep the waste: a click during a
/// four-minute cold load would wait for it and then load anyway, so the user
/// pays for two models to arrive somewhere they wanted one. The ticket is what
/// avoids that. A request takes one *before* queueing, so by the time it holds
/// the gate it can tell whether anything newer arrived while it waited, and a
/// load nobody is asking for any more ends without spawning anything.
///
/// One gate guards one model slot. A daemon that holds several models at once
/// keeps a gate per slot, so a request for one slot never supersedes a load
/// into another. Take it in the one function every load of that slot passes
/// through: a caller that skipped it would look exactly like the bug above.
#[derive(Debug, Default)]
pub struct LoadGate {
    /// Held for the whole of a load, so only one runs at a time.
    gate: tokio::sync::Mutex<()>,
    /// Bumped by every request as it arrives. Whoever holds the newest ticket
    /// is the only one that should still be loading.
    newest: std::sync::atomic::AtomicU64,
}

impl LoadGate {
    /// Claim a place in line.
    ///
    /// Must be called *before* awaiting [`Self::enter`]: a request that takes
    /// its ticket after queueing cannot be told apart from the one that
    /// superseded it.
    pub fn ticket(&self) -> u64 {
        self.newest
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .wrapping_add(1)
    }

    /// Wait for the gate, then report whether `ticket` is still the newest.
    ///
    /// `None` means a later request arrived while this one waited. That one
    /// will load what the user actually asked for, so this one should stop.
    ///
    /// The guard is returned rather than held inside, so the caller's scope
    /// decides how long the gate stays shut — which is the whole load.
    pub async fn enter(&self, ticket: u64) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        let guard = self.gate.lock().await;
        (self.newest.load(std::sync::atomic::Ordering::SeqCst) == ticket).then_some(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::LoadGate;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The whole point: two loads never overlap, and the one the user has
    /// stopped asking for never starts.
    ///
    /// Shaped as the bug was — a slow load already running when a second
    /// request arrives, then a third. The first is inside the gate, so it
    /// finishes; the second is superseded while it waits and must not run; the
    /// third is what the user actually wants.
    #[tokio::test]
    async fn a_superseded_load_never_starts_and_none_overlap() {
        let gate = Arc::new(LoadGate::default());
        let running = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));

        // The load already in flight, holding the gate.
        let first = gate.ticket();
        let held = gate
            .enter(first)
            .await
            .expect("the first is not superseded");
        running.fetch_add(1, Ordering::SeqCst);

        // Two more arrive while it runs. Tickets are taken now, as a real
        // request would — that is what makes the second detectable as stale.
        let second = gate.ticket();
        let third = gate.ticket();

        let mut waiting = Vec::new();
        for ticket in [second, third] {
            let gate = Arc::clone(&gate);
            let running = Arc::clone(&running);
            let started = Arc::clone(&started);
            waiting.push(tokio::spawn(async move {
                let Some(_guard) = gate.enter(ticket).await else {
                    return false;
                };
                started.fetch_add(1, Ordering::SeqCst);
                // If the gate let anyone else in, this sees it.
                assert_eq!(
                    running.fetch_add(1, Ordering::SeqCst),
                    0,
                    "two loads ran at once"
                );
                tokio::task::yield_now().await;
                running.fetch_sub(1, Ordering::SeqCst);
                true
            }));
        }

        // Let the queued pair reach the gate before the first releases it, so
        // this is a real wait rather than a sequence.
        tokio::task::yield_now().await;
        running.fetch_sub(1, Ordering::SeqCst);
        drop(held);

        let mut ran = 0;
        for task in waiting {
            if task.await.expect("no panic") {
                ran += 1;
            }
        }
        assert_eq!(ran, 1, "only the newest request should have loaded");
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "the superseded load must not start at all"
        );
    }

    /// One request on a quiet daemon is not superseded by itself.
    #[tokio::test]
    async fn a_lone_load_proceeds() {
        let gate = LoadGate::default();
        let ticket = gate.ticket();
        assert!(gate.enter(ticket).await.is_some());
    }

    /// Back-to-back loads each proceed: a ticket only goes stale while its
    /// holder is waiting, not after it has finished.
    #[tokio::test]
    async fn sequential_loads_each_proceed() {
        let gate = LoadGate::default();
        for _ in 0..3 {
            let ticket = gate.ticket();
            let guard = gate.enter(ticket).await;
            assert!(guard.is_some(), "a load with nothing behind it must run");
            drop(guard);
        }
    }
}
