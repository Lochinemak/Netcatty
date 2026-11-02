//! Authoritative tunnel registry with status publication.

use crate::error::ForwardResult;
use crate::tunnel::{Tunnel, TunnelSpec};
use netcatty_core::ipc::{PortForwardRuntimeEvent, PortForwardSnapshot, PortForwardStatusEvent, PortForwardTunnelInfo};
use netcatty_core::models::PortForwardingStatus;
use netcatty_ssh::SshConnection;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Events published by the registry.
#[derive(Debug, Clone)]
pub enum TunnelEvent {
    Status(PortForwardStatusEvent),
    Runtime(PortForwardRuntimeEvent),
}

/// Holds every tunnel (live, connecting or errored-but-not-removed).
pub struct TunnelRegistry {
    pub(crate) inner: dashmap::DashMap<String, RegistryEntry>,
    pub(crate) events: broadcast::Sender<TunnelEvent>,
    /// Monotonic generation of this registry instance (restarts bump it).
    pub epoch: u64,
    pub(crate) revision: std::sync::atomic::AtomicU64,
}

pub(crate) struct RegistryEntry {
    pub spec: TunnelSpec,
    pub status: PortForwardingStatus,
    pub error: Option<String>,
    pub tunnel: Option<Tunnel>,
    pub updated_at: i64,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            inner: dashmap::DashMap::new(),
            events,
            epoch: netcatty_core::ids::now_ms() as u64,
            revision: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.events.subscribe()
    }

    /// Register `spec` as `Connecting` and publish. Returns `false` when a
    /// live tunnel for the same `rule_id` already exists (caller reuses it).
    pub fn begin(&self, spec: TunnelSpec) -> bool {
        let _ = spec;
        todo!("insert Connecting entry + publish (forward agent task)")
    }

    /// Start the tunnel for an already registered spec on `connection`.
    pub async fn activate(&self, tunnel_id: &str, connection: Arc<SshConnection>) -> ForwardResult<()> {
        let _ = (tunnel_id, connection);
        todo!("Tunnel::start, store, publish Active; on error publish Error (forward agent task)")
    }

    pub fn fail(&self, tunnel_id: &str, error: impl Into<String>) {
        let _ = (tunnel_id, error.into());
        todo!()
    }

    pub async fn stop(&self, tunnel_id: &str) -> ForwardResult<()> {
        let _ = tunnel_id;
        todo!("stop tunnel, remove entry, publish Inactive + Remove (forward agent task)")
    }

    pub async fn stop_by_rule(&self, rule_id: &str) -> ForwardResult<usize> {
        let _ = rule_id;
        todo!()
    }

    pub async fn stop_all(&self) -> usize {
        todo!()
    }

    pub fn status(&self, tunnel_id: &str) -> Option<(PortForwardingStatus, Option<String>)> {
        self.inner.get(tunnel_id).map(|e| (e.status, e.error.clone()))
    }

    pub fn find_by_rule(&self, rule_id: &str) -> Option<PortForwardTunnelInfo> {
        let _ = rule_id;
        todo!()
    }

    pub fn snapshot(&self) -> PortForwardSnapshot {
        todo!()
    }

    pub fn list(&self) -> Vec<PortForwardTunnelInfo> {
        self.snapshot().tunnels
    }
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self::new()
    }
}
