//! Event emission helpers.

use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// Emit `event` with `payload` to every window. Failures are logged, never
/// propagated: a closed window must not break a backend task.
pub fn emit<T: Serialize + Clone>(app: &AppHandle, event: &str, payload: T) {
    if let Err(err) = app.emit(event, payload) {
        tracing::debug!(event, %err, "event emit failed");
    }
}
