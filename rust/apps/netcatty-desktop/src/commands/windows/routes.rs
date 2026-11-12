//! Per-window terminal output ownership (Electron: the session's
//! `webContentsId`, `attachHomeWebContentsIds`, `rendererSessionLifetime.cjs`
//! and the attach-popup grants of `terminalAttachRestore.cjs`).
//!
//! The backend keeps the *display* window of each session: the session pump
//! emits a routed session's output as `netcatty:data/<display label>`, which
//! only that window listens for (untracked sessions use the broadcast
//! `netcatty:data`). Every change is broadcast
//! (`netcatty:window:session-output-route`) and the renderer adapter still
//! drops broadcast output of sessions displayed elsewhere. The *owner* is the window that started
//! the session: its sessions are closed when it is destroyed. An attach popup
//! only borrows the display route (the owner does not change), and restoring
//! the route hands it back to a main window.

use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    /// Window that started the session (closed with it).
    owner: Option<String>,
    /// Window that renders the output.
    display: String,
    /// Display window before an attach popup took the route.
    home: Option<String>,
    revision: u64,
}

/// Broadcast payload / snapshot entry. `label: None` = no routing (every
/// window accepts the output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteChange {
    pub session_id: String,
    pub label: Option<String>,
    pub revision: u64,
}

#[derive(Default)]
pub struct OutputRoutes {
    routes: HashMap<String, Route>,
    revision: u64,
}

impl OutputRoutes {
    fn bump(&mut self) -> u64 {
        self.revision += 1;
        self.revision
    }

    fn change(session_id: &str, route: &Route) -> RouteChange {
        RouteChange {
            session_id: session_id.to_owned(),
            label: Some(route.display.clone()),
            revision: route.revision,
        }
    }

    /// `label` started `session_id`. The display follows the owner unless an
    /// attach popup currently holds it.
    pub fn track(&mut self, session_id: &str, label: &str) -> Option<RouteChange> {
        let revision = self.bump();
        let route = self
            .routes
            .entry(session_id.to_owned())
            .or_insert_with(|| Route {
                owner: None,
                display: label.to_owned(),
                home: None,
                revision,
            });
        route.owner = Some(label.to_owned());
        if route.home.is_some() || (route.display == label && route.revision != revision) {
            return None;
        }
        route.display = label.to_owned();
        route.revision = revision;
        Some(Self::change(session_id, route))
    }

    /// Current display window (`None`: untracked session).
    pub fn display_of(&self, session_id: &str) -> Option<&str> {
        self.routes.get(session_id).map(|r| r.display.as_str())
    }

    /// Display window before an attach took the route.
    pub fn home_of(&self, session_id: &str) -> Option<&str> {
        self.routes.get(session_id).and_then(|r| r.home.as_deref())
    }

    /// Move the display to `label` (attach popup). Returns the previous
    /// display window (`fallback_home` for an untracked session) and the
    /// change to broadcast.
    pub fn rebind(
        &mut self,
        session_id: &str,
        label: &str,
        fallback_home: &str,
    ) -> (Option<String>, RouteChange) {
        let revision = self.bump();
        let route = self
            .routes
            .entry(session_id.to_owned())
            .or_insert_with(|| Route {
                owner: None,
                display: fallback_home.to_owned(),
                home: None,
                revision,
            });
        let previous = route.display.clone();
        if previous != label && route.home.is_none() {
            route.home = Some(previous.clone());
        }
        route.display = label.to_owned();
        route.revision = revision;
        (Some(previous), Self::change(session_id, route))
    }

    /// Hand the display back to `target` and forget the attach home.
    pub fn restore(&mut self, session_id: &str, target: &str) -> Option<RouteChange> {
        let revision = self.bump();
        let route = self.routes.get_mut(session_id)?;
        route.home = None;
        route.display = target.to_owned();
        route.revision = revision;
        Some(Self::change(session_id, route))
    }

    pub fn remove(&mut self, session_id: &str) -> Option<RouteChange> {
        self.routes.remove(session_id)?;
        let revision = self.bump();
        Some(RouteChange {
            session_id: session_id.to_owned(),
            label: None,
            revision,
        })
    }

    /// Sessions started by `label`.
    pub fn owned_by(&self, label: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .routes
            .iter()
            .filter(|(_, r)| r.owner.as_deref() == Some(label))
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Sessions whose display (or attach home) is `label`.
    pub fn displayed_by(&self, label: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .routes
            .iter()
            .filter(|(_, r)| r.display == label)
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Drop routes of sessions that no longer exist.
    pub fn retain(&mut self, mut alive: impl FnMut(&str) -> bool) -> Vec<RouteChange> {
        let dead: Vec<String> = self
            .routes
            .keys()
            .filter(|id| !alive(id))
            .cloned()
            .collect();
        dead.iter().filter_map(|id| self.remove(id)).collect()
    }

    pub fn snapshot(&self) -> Vec<RouteChange> {
        let mut all: Vec<RouteChange> = self
            .routes
            .iter()
            .map(|(id, route)| Self::change(id, route))
            .collect();
        all.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        all
    }
}

#[derive(Debug, Clone)]
struct Grant {
    session_id: String,
    label: String,
    close_prepared: bool,
}

/// Attach-popup authorizations: a random token bound to one session and the
/// popup window it was issued to.
#[derive(Default)]
pub struct AttachGrants {
    grants: HashMap<String, Grant>,
}

impl AttachGrants {
    pub fn register(&mut self, token: &str, session_id: &str, label: &str) -> bool {
        if token.is_empty() || session_id.is_empty() || label.is_empty() {
            return false;
        }
        self.grants.insert(
            token.to_owned(),
            Grant {
                session_id: session_id.to_owned(),
                label: label.to_owned(),
                close_prepared: false,
            },
        );
        true
    }

    pub fn validate(&self, token: &str, session_id: &str, label: &str) -> bool {
        !token.is_empty()
            && !session_id.is_empty()
            && self
                .grants
                .get(token)
                .is_some_and(|g| g.session_id == session_id && g.label == label)
    }

    pub fn mark_close_prepared(&mut self, token: &str, session_id: &str, label: &str) -> bool {
        if !self.validate(token, session_id, label) {
            return false;
        }
        if let Some(grant) = self.grants.get_mut(token) {
            grant.close_prepared = true;
        }
        true
    }

    pub fn is_close_prepared(&self, token: &str) -> bool {
        self.grants.get(token).is_some_and(|g| g.close_prepared)
    }

    pub fn release(&mut self, token: &str) {
        self.grants.remove(token);
    }

    pub fn release_session(&mut self, session_id: &str) {
        self.grants.retain(|_, g| g.session_id != session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking_routes_output_to_the_starting_window() {
        let mut routes = OutputRoutes::default();
        let change = routes.track("s1", "session-1").unwrap();
        assert_eq!(change.label.as_deref(), Some("session-1"));
        assert_eq!(routes.display_of("s1"), Some("session-1"));
        // Re-tracking by the same window is not a change.
        assert!(routes.track("s1", "session-1").is_none());
        assert_eq!(routes.owned_by("session-1"), ["s1"]);
        assert!(routes.owned_by("main").is_empty());
    }

    #[test]
    fn display_rebind_is_not_an_ownership_handoff_but_restore_moves_display() {
        let mut routes = OutputRoutes::default();
        routes.track("s", "main");
        let (previous, change) = routes.rebind("s", "terminal-popup-1", "main");
        assert_eq!(previous.as_deref(), Some("main"));
        assert_eq!(change.label.as_deref(), Some("terminal-popup-1"));
        assert_eq!(routes.home_of("s"), Some("main"));
        // The popup does not own the session: closing it must not close s.
        assert!(routes.owned_by("terminal-popup-1").is_empty());
        assert_eq!(routes.owned_by("main"), ["s"]);
        // A reconnect of the owner while attached keeps the popup display.
        assert!(routes.track("s", "main").is_none());
        assert_eq!(routes.display_of("s"), Some("terminal-popup-1"));
        let restored = routes.restore("s", "main").unwrap();
        assert_eq!(restored.label.as_deref(), Some("main"));
        assert!(restored.revision > change.revision);
        assert_eq!(routes.home_of("s"), None);
    }

    #[test]
    fn rebinding_an_untracked_session_uses_the_fallback_home() {
        let mut routes = OutputRoutes::default();
        let (previous, _) = routes.rebind("s", "terminal-popup-1", "main");
        assert_eq!(previous.as_deref(), Some("main"));
        assert_eq!(routes.home_of("s"), Some("main"));
        // A second rebind keeps the original home.
        routes.rebind("s", "terminal-popup-2", "main");
        assert_eq!(routes.home_of("s"), Some("main"));
    }

    #[test]
    fn dead_sessions_are_pruned_with_an_unroute_change() {
        let mut routes = OutputRoutes::default();
        routes.track("a", "main");
        routes.track("b", "main");
        let changes = routes.retain(|id| id == "a");
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].session_id, "b");
        assert_eq!(changes[0].label, None);
        assert_eq!(routes.snapshot().len(), 1);
        assert!(routes.restore("b", "main").is_none());
    }

    #[test]
    fn attach_grants_are_bound_to_session_and_window() {
        let mut grants = AttachGrants::default();
        assert!(grants.register("tok", "s", "terminal-popup-1"));
        assert!(!grants.register("", "s", "w"));
        assert!(grants.validate("tok", "s", "terminal-popup-1"));
        assert!(!grants.validate("tok", "other", "terminal-popup-1"));
        assert!(!grants.validate("tok", "s", "main"));
        assert!(!grants.validate("", "s", "terminal-popup-1"));
        assert!(!grants.mark_close_prepared("tok", "s", "main"));
        assert!(!grants.is_close_prepared("tok"));
        assert!(grants.mark_close_prepared("tok", "s", "terminal-popup-1"));
        assert!(grants.is_close_prepared("tok"));
        grants.release_session("s");
        assert!(!grants.validate("tok", "s", "terminal-popup-1"));
    }
}
