//! Per-runtime quotas (port of `electron/plugins/quotaManager.cjs`).
//!
//! Message rate, capability rate / concurrency, log rate and byte windows
//! are enforced exactly like the Electron host. CPU / memory sampling of the
//! runtime process is not ported: browser runtimes live inside the shared
//! webview process (no per-plugin OS process to sample) and the Node sidecar
//! is bounded by its own process lifetime.

use crate::error::{codes, PluginError, PluginResult};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct Quotas {
    pub message_burst: f64,
    pub messages_per_second: f64,
    pub concurrent_capabilities: usize,
    pub capability_burst: f64,
    pub capabilities_per_minute: f64,
    pub log_writes_per_minute: f64,
    pub bytes_per_minute: u64,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            message_burst: 512.0,
            messages_per_second: 256.0,
            concurrent_capabilities: 32,
            capability_burst: 120.0,
            capabilities_per_minute: 600.0,
            log_writes_per_minute: 240.0,
            bytes_per_minute: 32 * 1024 * 1024,
        }
    }
}

pub fn quota_error(message: impl Into<String>) -> PluginError {
    PluginError::rpc_with(codes::RESOURCE_EXHAUSTED, message, json!({ "pluginCode": "resource_exhausted" }))
}

/// `TokenBucket` (refill per millisecond).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_ms: f64,
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_ms: f64) -> Self {
        Self { capacity, refill_per_ms, tokens: capacity, updated: Instant::now() }
    }
    pub fn consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.updated).as_secs_f64() * 1000.0;
        self.tokens = (self.tokens + elapsed * self.refill_per_ms).min(self.capacity);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[derive(Default)]
struct State {
    messages: HashMap<String, TokenBucket>,
    capabilities: HashMap<String, TokenBucket>,
    logs: HashMap<String, TokenBucket>,
    concurrent: HashMap<String, usize>,
    bytes: HashMap<String, (Instant, u64)>,
}

#[derive(Default)]
pub struct QuotaManager {
    pub quotas: Quotas,
    state: Mutex<State>,
}

/// Releases one concurrent capability slot on drop.
pub struct CapabilitySlot<'a> {
    manager: &'a QuotaManager,
    runtime_id: String,
}

impl Drop for CapabilitySlot<'_> {
    fn drop(&mut self) {
        let mut state = self.manager.state.lock();
        if let Some(count) = state.concurrent.get_mut(&self.runtime_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.concurrent.remove(&self.runtime_id);
            }
        }
    }
}

impl QuotaManager {
    pub fn new(quotas: Quotas) -> Self {
        Self { quotas, state: Mutex::new(State::default()) }
    }

    /// Transport guard: one token per inbound runtime message.
    pub fn guard_message(&self, runtime_id: &str) -> PluginResult<()> {
        let q = self.quotas;
        let mut state = self.state.lock();
        let bucket = state
            .messages
            .entry(runtime_id.to_string())
            .or_insert_with(|| TokenBucket::new(q.message_burst, q.messages_per_second / 1000.0));
        if bucket.consume() {
            Ok(())
        } else {
            Err(quota_error("Plugin runtime message rate exceeded"))
        }
    }

    /// Capability middleware: rate, log rate and concurrency.
    pub fn enter_capability(&self, runtime_id: &str, method: &str) -> PluginResult<CapabilitySlot<'_>> {
        let q = self.quotas;
        let mut state = self.state.lock();
        if state.concurrent.get(runtime_id).copied().unwrap_or(0) >= q.concurrent_capabilities {
            return Err(quota_error("Plugin concurrent capability limit exceeded"));
        }
        let bucket = state
            .capabilities
            .entry(runtime_id.to_string())
            .or_insert_with(|| TokenBucket::new(q.capability_burst, q.capabilities_per_minute / 60_000.0));
        if !bucket.consume() {
            return Err(quota_error("Plugin capability request rate exceeded"));
        }
        if method == "log.write" {
            let bucket = state
                .logs
                .entry(runtime_id.to_string())
                .or_insert_with(|| TokenBucket::new(q.log_writes_per_minute, q.log_writes_per_minute / 60_000.0));
            if !bucket.consume() {
                return Err(quota_error("Plugin log rate exceeded"));
            }
        }
        *state.concurrent.entry(runtime_id.to_string()).or_insert(0) += 1;
        Ok(CapabilitySlot { manager: self, runtime_id: runtime_id.to_string() })
    }

    pub fn charge_bytes(&self, runtime_id: &str, category: &str, bytes: u64) -> PluginResult<()> {
        let key = format!("{runtime_id}\0{category}");
        let mut state = self.state.lock();
        let now = Instant::now();
        let window = state.bytes.entry(key).or_insert((now, 0));
        if now.duration_since(window.0).as_millis() >= 60_000 {
            *window = (now, 0);
        }
        window.1 += bytes;
        if window.1 > self.quotas.bytes_per_minute {
            return Err(quota_error(format!("Plugin {category} byte quota exceeded")));
        }
        Ok(())
    }

    pub fn release_runtime(&self, runtime_id: &str) {
        let mut state = self.state.lock();
        state.messages.remove(runtime_id);
        state.capabilities.remove(runtime_id);
        state.logs.remove(runtime_id);
        state.concurrent.remove(runtime_id);
        let prefix = format!("{runtime_id}\0");
        state.bytes.retain(|k, _| !k.starts_with(&prefix));
    }

    pub fn shutdown(&self) {
        *self.state.lock() = State::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_concurrency_and_bytes() {
        let manager = QuotaManager::new(Quotas { concurrent_capabilities: 1, bytes_per_minute: 10, ..Quotas::default() });
        let slot = manager.enter_capability("r", "storage.get").unwrap();
        assert!(manager.enter_capability("r", "storage.get").is_err());
        drop(slot);
        assert!(manager.enter_capability("r", "storage.get").is_ok());
        manager.charge_bytes("r", "network", 8).unwrap();
        assert!(manager.charge_bytes("r", "network", 8).is_err());
        manager.release_runtime("r");
        manager.charge_bytes("r", "network", 8).unwrap();
    }

    #[test]
    fn message_burst() {
        let manager = QuotaManager::new(Quotas { message_burst: 2.0, messages_per_second: 0.0, ..Quotas::default() });
        manager.guard_message("r").unwrap();
        manager.guard_message("r").unwrap();
        assert!(manager.guard_message("r").is_err());
    }
}
