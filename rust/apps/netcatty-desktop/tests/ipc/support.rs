//! Shared event harness for the headless IPC tests: collect the payloads of
//! one event channel and wait for a predicate over them.
//!
//! # Why this is not just a poll loop
//!
//! Tauri dispatches Rust-side listeners under `handlers.try_lock()`
//! (`tauri::event::listener::Listeners::emit_filter`). An `emit` that loses
//! that lock is **not** delivered — it is pushed onto a pending queue, and
//! the queue is only drained by `flush_pending`, which runs after an `emit`
//! that reached at least one listener. `listen` is queued the same way.
//!
//! So an emit on a quiet channel is lost for good when it races an emit on a
//! channel that has no listener: the loser pends, and the winner finds no
//! handler, so it never flushes. That is one PTY chunk on `netcatty:data`
//! landing at the same instant as a single receipt — rare, load-dependent,
//! and exactly the two CI flakes in `ipc_zmodem_terminal` (2026-11-12 on
//! `main`, 2026-11-14 on PR #14): a `netcatty:paste-write` receipt and a
//! trailing `netcatty:data` chunk that were emitted and never arrived. Both
//! tests then sat out their whole timeout — the budgets were never tight,
//! they were waiting on something already dropped.
//!
//! Every wait here therefore *pumps*: it emits a private no-op event that
//! the harness listens for, which reaches a listener and so drains the
//! queue. [`install_pump`] registers that listener while the app is still
//! quiet, before anything can race it.

use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tauri::test::MockRuntime;
use tauri::{App, AppHandle, Emitter, Listener, Manager};

/// Private channel, emitted only to give Tauri a reason to flush.
const PUMP_EVENT: &str = "netcatty:test:pump";

/// How long a pump keeps trying before it gives up on the dispatcher.
const PUMP_TIMEOUT: Duration = Duration::from_secs(5);

/// Gap between polls while waiting. The fastest of the per-file helpers this
/// module replaced, so no test waits longer than it used to.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The pump listener's counter, kept in the app's managed state so a
/// [`Pumper`] can be built from nothing but an `AppHandle` — `wait_until` is
/// also called from worker threads, which have no `&App`.
struct Pump(Arc<AtomicUsize>);

/// Register the pump listener. Call this in `build_app`, right after the app
/// is built: nothing is emitting yet, so the registration cannot be queued.
pub(crate) fn install_pump(app: &App<MockRuntime>) {
    let count = Arc::new(AtomicUsize::new(0));
    let bump = count.clone();
    app.listen_any(PUMP_EVENT, move |_| {
        bump.fetch_add(1, Ordering::SeqCst);
    });
    app.manage(Pump(count));
}

/// Drains Tauri's pending-event queue on demand (see the module docs).
pub(crate) struct Pumper {
    app: AppHandle<MockRuntime>,
    count: Arc<AtomicUsize>,
}

impl Pumper {
    pub(crate) fn of(app: &AppHandle<MockRuntime>) -> Self {
        let count = app
            .try_state::<Pump>()
            .expect("install_pump() was not called in build_app()")
            .0
            .clone();
        Self {
            app: app.clone(),
            count,
        }
    }

    /// Emit the no-op event until it comes back. The round trip is the
    /// proof: our listener ran, so `flush_pending` ran with it, so anything
    /// that had been queued — a `listen`, an event we are waiting for — has
    /// been delivered. Never call this while holding the collected payloads:
    /// the flush pushes into them from this thread.
    pub(crate) fn pump(&self) {
        let before = self.count.load(Ordering::SeqCst);
        let deadline = Instant::now() + PUMP_TIMEOUT;
        loop {
            let _ = self.app.emit(PUMP_EVENT, ());
            if self.count.load(Ordering::SeqCst) != before {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the event dispatcher never flushed: {PUMP_EVENT} did not come back in {PUMP_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The payloads seen on one event channel.
pub(crate) struct Events {
    pump: Pumper,
    seen: Arc<Mutex<Vec<Value>>>,
}

/// Record every payload of `event` emitted by the app.
pub(crate) fn collect(app: &App<MockRuntime>, event: &str) -> Events {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    app.listen_any(event.to_string(), move |e| {
        let payload: Value = serde_json::from_str(e.payload()).unwrap_or(Value::Null);
        sink.lock().unwrap().push(payload);
    });
    let events = Events {
        pump: Pumper::of(app.app_handle()),
        seen,
    };
    // The `listen` above may have been queued; flush before the caller acts
    // on the session, or events emitted in the gap are never recorded.
    events.pump.pump();
    events
}

impl Events {
    /// The payloads so far, after a flush.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Vec<Value>> {
        self.pump.pump();
        self.seen.lock().unwrap()
    }
}

/// Poll `pred` over the collected payloads until it holds or `timeout`
/// passes. What was already delivered is checked before pumping, so the
/// common case — the event is in — costs nothing extra.
pub(crate) fn wait_for(
    events: &Events,
    timeout: Duration,
    pred: impl Fn(&[Value]) -> bool,
) -> bool {
    let start = Instant::now();
    loop {
        if pred(&events.seen.lock().unwrap()) {
            return true;
        }
        events.pump.pump();
        if pred(&events.seen.lock().unwrap()) {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// [`wait_for`] for a predicate that reads something other than one event
/// channel (window lists, several channels at once).
pub(crate) fn wait_until(
    app: &AppHandle<MockRuntime>,
    timeout: Duration,
    mut pred: impl FnMut() -> bool,
) -> bool {
    let pump = Pumper::of(app);
    let start = Instant::now();
    loop {
        if pred() {
            return true;
        }
        pump.pump();
        if pred() {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}
