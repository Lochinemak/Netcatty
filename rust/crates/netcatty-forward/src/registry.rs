//! Authoritative tunnel registry with status publication.
//!
//! Mirrors `portForwardingBridge.cjs`: every state change bumps a monotonic
//! `revision` and publishes both a `PortForwardStatusEvent` and a
//! `PortForwardRuntimeEvent::Upsert` carrying the same `(epoch, revision)`;
//! removal is a distinct revision (`Runtime::Remove`) after the `Inactive`
//! upsert so subscribers can tell "stopped" from "retained error record".

use crate::error::{ForwardError, ForwardResult};
use crate::tunnel::{Tunnel, TunnelSpec};
use netcatty_core::ipc::{
    PortForwardRuntimeEvent, PortForwardSnapshot, PortForwardStatusEvent, PortForwardTunnelInfo,
};
use netcatty_core::models::PortForwardingStatus;
use netcatty_ssh::SshConnection;
use std::sync::atomic::Ordering;
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
    /// Set when a stop failed to release the server-side listen.
    pub cleanup_failed: bool,
}

impl RegistryEntry {
    fn info(&self, tunnel_id: &str) -> PortForwardTunnelInfo {
        PortForwardTunnelInfo {
            tunnel_id: tunnel_id.to_string(),
            rule_id: self.spec.rule_id.clone(),
            forward_type: self.spec.forward_type,
            status: self.status,
            error: self.error.clone(),
            local_port: self.spec.local_port,
            bind_address: self.spec.bind_address.clone(),
            remote_host: self.spec.remote_host.clone(),
            remote_port: self.spec.remote_port,
            host_id: self.spec.host_id.clone(),
            hostname: self.spec.hostname.clone(),
            updated_at: self.updated_at,
        }
    }
}

fn is_reusable(status: PortForwardingStatus) -> bool {
    matches!(
        status,
        PortForwardingStatus::Active | PortForwardingStatus::Connecting
    )
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

    /// Current revision (last published).
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    fn next_revision(&self) -> u64 {
        self.revision.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Update an entry's status and publish `Status` + `Runtime::Upsert`.
    fn publish_status(
        &self,
        tunnel_id: &str,
        status: PortForwardingStatus,
        error: Option<String>,
        cleanup_failed: Option<bool>,
    ) {
        let (info, cleanup_required) = {
            let Some(mut entry) = self.inner.get_mut(tunnel_id) else {
                return;
            };
            entry.status = status;
            entry.error = error.clone();
            if let Some(flag) = cleanup_failed {
                entry.cleanup_failed = flag;
            }
            entry.updated_at = netcatty_core::ids::now_ms();
            (entry.info(tunnel_id), entry.cleanup_failed)
        };
        let revision = self.next_revision();
        let _ = self
            .events
            .send(TunnelEvent::Status(PortForwardStatusEvent {
                tunnel_id: tunnel_id.to_string(),
                status,
                error,
                rule_id: info.rule_id.clone(),
                epoch: self.epoch,
                revision,
                cleanup_required,
            }));
        let _ = self
            .events
            .send(TunnelEvent::Runtime(PortForwardRuntimeEvent::Upsert {
                epoch: self.epoch,
                revision,
                tunnel: info,
            }));
    }

    fn publish_remove(&self, tunnel_id: &str) {
        let revision = self.next_revision();
        let _ = self
            .events
            .send(TunnelEvent::Runtime(PortForwardRuntimeEvent::Remove {
                epoch: self.epoch,
                revision,
                tunnel_id: tunnel_id.to_string(),
            }));
    }

    /// Register `spec` as `Connecting` and publish. Returns `false` when a
    /// live tunnel for the same `rule_id` already exists (caller reuses it).
    pub fn begin(&self, spec: TunnelSpec) -> bool {
        if let Some(rule_id) = spec.rule_id.as_deref() {
            let live = self
                .inner
                .iter()
                .any(|e| e.spec.rule_id.as_deref() == Some(rule_id) && is_reusable(e.status));
            if live {
                return false;
            }
        }
        if self
            .inner
            .get(&spec.tunnel_id)
            .is_some_and(|e| is_reusable(e.status))
        {
            return false;
        }
        let tunnel_id = spec.tunnel_id.clone();
        self.inner.insert(
            tunnel_id.clone(),
            RegistryEntry {
                spec,
                status: PortForwardingStatus::Connecting,
                error: None,
                tunnel: None,
                updated_at: netcatty_core::ids::now_ms(),
                cleanup_failed: false,
            },
        );
        self.publish_status(
            &tunnel_id,
            PortForwardingStatus::Connecting,
            None,
            Some(false),
        );
        true
    }

    /// Start the tunnel for an already registered spec on `connection`.
    pub async fn activate(
        &self,
        tunnel_id: &str,
        connection: Arc<SshConnection>,
    ) -> ForwardResult<()> {
        let spec = self
            .inner
            .get(tunnel_id)
            .map(|e| e.spec.clone())
            .ok_or_else(|| ForwardError::NotFound(tunnel_id.to_string()))?;
        match Tunnel::start(spec, connection).await {
            Ok(tunnel) => self.adopt(tunnel_id, tunnel).await,
            Err(err) => {
                self.fail(tunnel_id, err.to_string());
                Err(err)
            }
        }
    }

    /// Attach an already started tunnel to its registered entry and publish
    /// `Active`. If the entry was removed meanwhile (stop raced the start),
    /// the tunnel is stopped and `Cancelled` is returned.
    pub async fn adopt(&self, tunnel_id: &str, tunnel: Tunnel) -> ForwardResult<()> {
        let rejected = match self.inner.get_mut(tunnel_id) {
            Some(mut entry) if entry.status == PortForwardingStatus::Connecting => {
                entry.tunnel = Some(tunnel);
                None
            }
            _ => Some(tunnel),
        };
        if let Some(tunnel) = rejected {
            let _ = tunnel.stop().await;
            return Err(ForwardError::Cancelled);
        }
        self.publish_status(tunnel_id, PortForwardingStatus::Active, None, Some(false));
        Ok(())
    }

    pub fn fail(&self, tunnel_id: &str, error: impl Into<String>) {
        let error = error.into();
        if self.inner.get(tunnel_id).is_none() {
            return;
        }
        self.publish_status(tunnel_id, PortForwardingStatus::Error, Some(error), None);
    }

    pub async fn stop(&self, tunnel_id: &str) -> ForwardResult<()> {
        let tunnel = {
            let Some(mut entry) = self.inner.get_mut(tunnel_id) else {
                return Err(ForwardError::NotFound(tunnel_id.to_string()));
            };
            entry.tunnel.take()
        };
        if let Some(tunnel) = tunnel {
            if let Err(err) = tunnel.stop().await {
                // Keep the record so the UI can retry the cleanup.
                let message = err.to_string();
                if let Some(mut entry) = self.inner.get_mut(tunnel_id) {
                    entry.tunnel = Some(tunnel);
                }
                self.publish_status(
                    tunnel_id,
                    PortForwardingStatus::Error,
                    Some(message),
                    Some(true),
                );
                return Err(err);
            }
        }
        self.publish_status(tunnel_id, PortForwardingStatus::Inactive, None, Some(false));
        self.inner.remove(tunnel_id);
        self.publish_remove(tunnel_id);
        Ok(())
    }

    pub async fn stop_by_rule(&self, rule_id: &str) -> ForwardResult<usize> {
        let ids: Vec<String> = self
            .inner
            .iter()
            .filter(|e| e.spec.rule_id.as_deref() == Some(rule_id))
            .map(|e| e.key().clone())
            .collect();
        let mut stopped = 0;
        let mut first_error = None;
        for id in ids {
            match self.stop(&id).await {
                Ok(()) => stopped += 1,
                Err(ForwardError::NotFound(_)) => {}
                Err(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }
        match first_error {
            Some(err) if stopped == 0 => Err(err),
            _ => Ok(stopped),
        }
    }

    pub async fn stop_all(&self) -> usize {
        let ids: Vec<String> = self.inner.iter().map(|e| e.key().clone()).collect();
        let mut stopped = 0;
        for id in ids {
            if self.stop(&id).await.is_ok() {
                stopped += 1;
            }
        }
        stopped
    }

    pub fn status(&self, tunnel_id: &str) -> Option<(PortForwardingStatus, Option<String>)> {
        self.inner
            .get(tunnel_id)
            .map(|e| (e.status, e.error.clone()))
    }

    /// Address the local listener of an active local / dynamic tunnel bound
    /// (resolves `localPort: 0` to the port the OS picked).
    pub fn local_addr(&self, tunnel_id: &str) -> Option<std::net::SocketAddr> {
        self.inner
            .get(tunnel_id)
            .and_then(|e| e.tunnel.as_ref().and_then(|t| t.local_addr()))
    }

    pub fn find_by_rule(&self, rule_id: &str) -> Option<PortForwardTunnelInfo> {
        let mut matches: Vec<PortForwardTunnelInfo> = self
            .inner
            .iter()
            .filter(|e| e.spec.rule_id.as_deref() == Some(rule_id))
            .map(|e| e.info(e.key()))
            .collect();
        // Prefer a live tunnel over a retained error record.
        matches.sort_by_key(|info| {
            (
                !is_reusable(info.status),
                std::cmp::Reverse(info.updated_at),
            )
        });
        matches.into_iter().next()
    }

    pub fn snapshot(&self) -> PortForwardSnapshot {
        let mut tunnels: Vec<PortForwardTunnelInfo> =
            self.inner.iter().map(|e| e.info(e.key())).collect();
        tunnels.sort_by(|a, b| a.tunnel_id.cmp(&b.tunnel_id));
        PortForwardSnapshot {
            epoch: self.epoch,
            revision: self.revision(),
            tunnels,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use netcatty_core::models::PortForwardingType;

    fn spec(id: &str, rule: Option<&str>) -> TunnelSpec {
        TunnelSpec {
            tunnel_id: id.into(),
            rule_id: rule.map(str::to_string),
            forward_type: PortForwardingType::Local,
            bind_address: "127.0.0.1".into(),
            local_port: 8080,
            remote_host: Some("db".into()),
            remote_port: Some(5432),
            host_id: Some("h1".into()),
            hostname: "example".into(),
        }
    }

    fn drain(rx: &mut broadcast::Receiver<TunnelEvent>) -> Vec<TunnelEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[tokio::test]
    async fn begin_fail_stop_lifecycle_publishes_events() {
        let registry = TunnelRegistry::new();
        let mut rx = registry.subscribe();

        assert!(registry.begin(spec("t1", Some("r1"))));
        assert_eq!(
            registry.status("t1"),
            Some((PortForwardingStatus::Connecting, None))
        );
        let events = drain(&mut rx);
        assert_eq!(events.len(), 2);
        match &events[0] {
            TunnelEvent::Status(s) => {
                assert_eq!(s.tunnel_id, "t1");
                assert_eq!(s.status, PortForwardingStatus::Connecting);
                assert_eq!(s.rule_id.as_deref(), Some("r1"));
                assert_eq!(s.revision, 1);
                assert_eq!(s.epoch, registry.epoch);
                assert!(!s.cleanup_required);
            }
            other => panic!("unexpected {other:?}"),
        }
        match &events[1] {
            TunnelEvent::Runtime(PortForwardRuntimeEvent::Upsert {
                revision, tunnel, ..
            }) => {
                assert_eq!(*revision, 1);
                assert_eq!(tunnel.status, PortForwardingStatus::Connecting);
                assert_eq!(tunnel.local_port, 8080);
            }
            other => panic!("unexpected {other:?}"),
        }

        // Same rule while connecting → reuse.
        assert!(!registry.begin(spec("t2", Some("r1"))));
        assert!(registry.status("t2").is_none());
        // Different rule is fine.
        assert!(registry.begin(spec("t3", Some("r2"))));
        drain(&mut rx);

        registry.fail("t1", "connect refused");
        assert_eq!(
            registry.status("t1"),
            Some((PortForwardingStatus::Error, Some("connect refused".into())))
        );
        let events = drain(&mut rx);
        assert!(
            matches!(&events[0], TunnelEvent::Status(s) if s.status == PortForwardingStatus::Error && s.revision == 3)
        );

        // An errored record is not reusable: a new begin for the rule works.
        assert!(registry.begin(spec("t4", Some("r1"))));
        assert_eq!(registry.find_by_rule("r1").unwrap().tunnel_id, "t4");
        drain(&mut rx);

        registry.stop("t1").await.unwrap();
        assert!(registry.status("t1").is_none());
        let events = drain(&mut rx);
        assert_eq!(events.len(), 3);
        assert!(
            matches!(&events[0], TunnelEvent::Status(s) if s.status == PortForwardingStatus::Inactive)
        );
        assert!(matches!(
            &events[1],
            TunnelEvent::Runtime(PortForwardRuntimeEvent::Upsert { .. })
        ));
        match &events[2] {
            TunnelEvent::Runtime(PortForwardRuntimeEvent::Remove {
                tunnel_id,
                revision,
                ..
            }) => {
                assert_eq!(tunnel_id, "t1");
                assert_eq!(*revision, 6);
            }
            other => panic!("unexpected {other:?}"),
        }

        assert!(matches!(
            registry.stop("nope").await,
            Err(ForwardError::NotFound(_))
        ));
        assert_eq!(registry.stop_by_rule("r2").await.unwrap(), 1);
        assert_eq!(registry.stop_by_rule("r2").await.unwrap(), 0);
        assert_eq!(registry.stop_all().await, 1);
        assert!(registry.list().is_empty());
    }

    #[tokio::test]
    async fn snapshot_lists_entries_with_current_revision() {
        let registry = TunnelRegistry::new();
        assert!(registry.begin(spec("b", None)));
        assert!(registry.begin(spec("a", None)));
        let snap = registry.snapshot();
        assert_eq!(snap.epoch, registry.epoch);
        assert_eq!(snap.revision, 2);
        let ids: Vec<&str> = snap.tunnels.iter().map(|t| t.tunnel_id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
        assert!(snap
            .tunnels
            .iter()
            .all(|t| t.status == PortForwardingStatus::Connecting));
        assert_eq!(snap.tunnels[0].hostname, "example");
        assert_eq!(snap.tunnels[0].remote_port, Some(5432));

        // Rule-less specs never collide; same tunnel id while live does.
        assert!(!registry.begin(spec("a", None)));
        assert!(registry.find_by_rule("missing").is_none());
    }
}
