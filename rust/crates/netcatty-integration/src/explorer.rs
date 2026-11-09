//! Windows Explorer "Open in Netcatty" folder / folder-background verbs
//! (Electron: `electron/explorerContextMenu.cjs`). Same keys, label, icon,
//! command line and schema versioning as the Electron build (and as the NSIS
//! installer hook), so an upgrade from Electron keeps working entries.
//!
//! The logic runs against the [`Registry`] trait: [`WindowsRegistry`] on
//! Windows (HKCU / HKLM through the registry API instead of `reg.exe`), and
//! an in-memory registry in tests.

use serde::Serialize;
use std::path::{Path, PathBuf};

pub const EXPLORER_CONTEXT_MENU_PREFERENCES_FILE: &str = "explorer-context-menu-preferences.json";
/// Records that a no-verb default-off probe completed. Never a user choice:
/// portable builds can share the data directory with a later installer.
pub const EXPLORER_CONTEXT_MENU_PROBE_FILE: &str = "explorer-context-menu-probe.json";
/// Bump when the verb command / label / icon contract changes.
/// v2: prefer `PORTABLE_EXECUTABLE_FILE`; v3: development entry path after
/// the executable.
pub const EXPLORER_CONTEXT_MENU_SCHEMA_VERSION: i64 = 3;
pub const SHELL_VERB: &str = "Netcatty";
pub const DIRECTORY_SHELL_KEY: &str = "Software\\Classes\\Directory\\shell\\Netcatty";
pub const DIRECTORY_BACKGROUND_SHELL_KEY: &str =
    "Software\\Classes\\Directory\\Background\\shell\\Netcatty";
pub const MENU_LABEL: &str = "Open in Netcatty";
/// Hides a verb in Explorer while keeping the key: the per-user override for
/// machine-wide (HKLM) verbs that cannot be deleted without elevation.
pub const SUPPRESSION_VALUE: &str = "ProgrammaticAccessOnly";
const OPEN_TERMINAL_PATH_ARG: &str = "--open-terminal-path";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Hive {
    CurrentUser,
    LocalMachine,
}

/// The registry operations the Electron code performed through `reg.exe`.
/// Value name `""` is the key's default value. Deleting something that does
/// not exist succeeds; writing creates missing keys.
pub trait Registry {
    fn key_exists(&self, hive: Hive, path: &str) -> bool;
    fn value_exists(&self, hive: Hive, path: &str, name: &str) -> bool;
    fn read_string(&self, hive: Hive, path: &str, name: &str) -> Option<String>;
    fn write_string(&self, hive: Hive, path: &str, name: &str, value: &str) -> bool;
    fn delete_key(&self, hive: Hive, path: &str) -> bool;
    fn delete_value(&self, hive: Hive, path: &str, name: &str) -> bool;
}

/// `{ success, enabled, supported }` as returned to the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExplorerResult {
    pub success: bool,
    pub enabled: bool,
    pub supported: bool,
}

impl ExplorerResult {
    fn unsupported() -> Self {
        Self {
            success: true,
            enabled: false,
            supported: false,
        }
    }
}

/// Executable plus optional development entry arguments for the verbs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchSpec {
    pub executable_path: String,
    pub app_args: Vec<String>,
}

/// `PORTABLE_EXECUTABLE_FILE` (a durable portable launcher) wins over the
/// running executable, which may live in a temporary unpack directory.
pub fn resolve_launch_spec(portable_executable_file: Option<&str>, exe: &Path) -> LaunchSpec {
    if let Some(portable) = portable_executable_file.map(str::trim).filter(|p| !p.is_empty()) {
        return LaunchSpec {
            executable_path: portable.to_owned(),
            app_args: Vec::new(),
        };
    }
    LaunchSpec {
        executable_path: exe.to_string_lossy().trim().to_owned(),
        app_args: Vec::new(),
    }
}

fn normalize_args(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|a| a.trim().to_owned())
        .filter(|a| !a.is_empty())
        .collect()
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

/// `"exe" ["app"] -- --open-terminal-path="%1."`: the path stays in one
/// token (`=`) and the trailing `.` dodges the `"C:\"` quote-escape bug.
pub fn build_command(executable_path: &str, placeholder: &str, app_args: &[String]) -> Option<String> {
    let exe = executable_path.trim();
    let placeholder = placeholder.trim();
    if exe.is_empty() || placeholder.is_empty() {
        return None;
    }
    let mut prefix = vec![quote(exe)];
    prefix.extend(normalize_args(app_args).iter().map(|a| quote(a)));
    Some(format!(
        "{} -- {OPEN_TERMINAL_PATH_ARG}=\"{placeholder}.\"",
        prefix.join(" ")
    ))
}

#[derive(Debug, Clone)]
struct VerbSpec<'a> {
    executable_path: &'a str,
    placeholder: &'a str,
    app_args: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreferenceRecord {
    enabled: bool,
    schema_version: i64,
    executable_path: String,
    app_args: Vec<String>,
}

/// Explorer integration bound to a registry and the app data directory.
pub struct ExplorerContextMenu<'a> {
    pub registry: &'a dyn Registry,
    pub data_dir: &'a Path,
    /// `false` everywhere but Windows: every operation reports unsupported.
    pub supported: bool,
}

impl<'a> ExplorerContextMenu<'a> {
    fn preference_path(&self) -> PathBuf {
        self.data_dir.join(EXPLORER_CONTEXT_MENU_PREFERENCES_FILE)
    }

    fn probe_path(&self) -> PathBuf {
        self.data_dir.join(EXPLORER_CONTEXT_MENU_PROBE_FILE)
    }

    fn read_json(path: &Path) -> Option<serde_json::Value> {
        if !path.exists() {
            return None;
        }
        match std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        {
            Some(value) => Some(value),
            None => {
                tracing::warn!(path = %path.display(), "failed to read Explorer context menu state");
                None
            }
        }
    }

    fn write_json(path: &Path, value: &serde_json::Value) -> bool {
        let result = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| {
                std::fs::write(
                    path,
                    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
                )
            });
        if let Err(err) = &result {
            tracing::warn!(path = %path.display(), %err, "failed to write Explorer context menu state");
        }
        result.is_ok()
    }

    fn probe_current(&self) -> bool {
        Self::read_json(&self.probe_path())
            .and_then(|v| v.get("schemaVersion").and_then(serde_json::Value::as_i64))
            .is_some_and(|v| v == EXPLORER_CONTEXT_MENU_SCHEMA_VERSION)
    }

    fn write_probe_marker(&self) -> bool {
        Self::write_json(
            &self.probe_path(),
            &serde_json::json!({ "schemaVersion": EXPLORER_CONTEXT_MENU_SCHEMA_VERSION }),
        )
    }

    fn read_preference(&self) -> Option<PreferenceRecord> {
        let value = Self::read_json(&self.preference_path())?;
        let enabled = value.get("enabled")?.as_bool()?;
        Some(PreferenceRecord {
            enabled,
            schema_version: value
                .get("schemaVersion")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            executable_path: value
                .get("executablePath")
                .and_then(serde_json::Value::as_str)
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
            app_args: value
                .get("appArgs")
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .map(|a| a.as_str().unwrap_or_default().trim().to_owned())
                        .filter(|a| !a.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Saved user choice, if any.
    pub fn read_enabled_preference(&self) -> Option<bool> {
        self.read_preference().map(|r| r.enabled)
    }

    pub fn write_enabled_preference(&self, enabled: bool, spec: &LaunchSpec) -> bool {
        let mut payload = serde_json::json!({
            "enabled": enabled,
            "schemaVersion": EXPLORER_CONTEXT_MENU_SCHEMA_VERSION,
        });
        let exe = spec.executable_path.trim();
        if !exe.is_empty() {
            payload["executablePath"] = serde_json::Value::String(exe.to_owned());
        }
        let args = normalize_args(&spec.app_args);
        if !args.is_empty() {
            payload["appArgs"] = serde_json::json!(args);
        }
        Self::write_json(&self.preference_path(), &payload)
    }

    // -- registry helpers ---------------------------------------------------

    fn delete_key_checked(&self, hive: Hive, path: &str) -> bool {
        !self.registry.key_exists(hive, path) || self.registry.delete_key(hive, path)
    }

    fn delete_value_checked(&self, hive: Hive, path: &str, name: &str) -> bool {
        !self.registry.value_exists(hive, path, name) || self.registry.delete_value(hive, path, name)
    }

    fn is_suppression_key(&self, hive: Hive, path: &str) -> bool {
        self.registry.key_exists(hive, path) && self.registry.value_exists(hive, path, SUPPRESSION_VALUE)
    }

    fn verb_is_current(&self, hive: Hive, key: &str, spec: &VerbSpec<'_>) -> bool {
        if !self.registry.key_exists(hive, key) {
            return false;
        }
        if hive == Hive::CurrentUser && self.is_suppression_key(hive, key) {
            return false;
        }
        let Some(expected) = build_command(spec.executable_path, spec.placeholder, spec.app_args) else {
            return false;
        };
        let expected_icon = format!("{},0", spec.executable_path);
        self.registry.read_string(hive, &format!("{key}\\command"), "").as_deref() == Some(&expected)
            && self.registry.read_string(hive, key, "MUIVerb").as_deref() == Some(MENU_LABEL)
            && self.registry.read_string(hive, key, "Icon").as_deref() == Some(expected_icon.as_str())
    }

    fn write_verb(&self, hive: Hive, key: &str, spec: &VerbSpec<'_>) -> bool {
        let Some(command) = build_command(spec.executable_path, spec.placeholder, spec.app_args) else {
            return false;
        };
        if self.verb_is_current(hive, key, spec) {
            return true;
        }
        let icon = format!("{},0", spec.executable_path);
        self.registry.write_string(hive, key, "MUIVerb", MENU_LABEL)
            && self.registry.write_string(hive, key, "Icon", &icon)
            && self.registry.write_string(hive, &format!("{key}\\command"), "", &command)
    }

    fn is_user_suppressed(&self) -> bool {
        self.is_suppression_key(Hive::CurrentUser, DIRECTORY_SHELL_KEY)
            && self.is_suppression_key(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY)
    }

    /// Hide both verbs for this user; a partial pair is rolled back without
    /// ever deleting a pre-existing working HKCU verb.
    fn write_user_suppression(&self) -> bool {
        let folder_existed = self.registry.key_exists(Hive::CurrentUser, DIRECTORY_SHELL_KEY);
        let background_existed = self
            .registry
            .key_exists(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY);
        let folder_ok = self
            .registry
            .write_string(Hive::CurrentUser, DIRECTORY_SHELL_KEY, SUPPRESSION_VALUE, "");
        let background_ok = self.registry.write_string(
            Hive::CurrentUser,
            DIRECTORY_BACKGROUND_SHELL_KEY,
            SUPPRESSION_VALUE,
            "",
        );
        if folder_ok && background_ok {
            return true;
        }
        for (ok, existed, key) in [
            (folder_ok, folder_existed, DIRECTORY_SHELL_KEY),
            (background_ok, background_existed, DIRECTORY_BACKGROUND_SHELL_KEY),
        ] {
            if !ok {
                continue;
            }
            if existed {
                self.delete_value_checked(Hive::CurrentUser, key, SUPPRESSION_VALUE);
            } else {
                self.delete_key_checked(Hive::CurrentUser, key);
            }
        }
        false
    }

    /// Remove per-user hides, keeping a hidden real install verb.
    fn clear_user_suppression(&self) -> bool {
        let mut ok = true;
        for key in [DIRECTORY_SHELL_KEY, DIRECTORY_BACKGROUND_SHELL_KEY] {
            if !self.is_suppression_key(Hive::CurrentUser, key) {
                continue;
            }
            let command = self
                .registry
                .read_string(Hive::CurrentUser, &format!("{key}\\command"), "");
            if command.is_some_and(|c| !c.trim().is_empty()) {
                if !self.delete_value_checked(Hive::CurrentUser, key, SUPPRESSION_VALUE) {
                    ok = false;
                }
            } else if !self.delete_key_checked(Hive::CurrentUser, key) {
                ok = false;
            }
        }
        ok
    }

    fn clear_user_shell_keys(&self) -> bool {
        let mut ok = true;
        for key in [DIRECTORY_SHELL_KEY, DIRECTORY_BACKGROUND_SHELL_KEY] {
            if !self.delete_key_checked(Hive::CurrentUser, key)
                && self.registry.key_exists(Hive::CurrentUser, key)
            {
                ok = false;
            }
        }
        ok
    }

    fn has_residual_user_shell_keys(&self) -> bool {
        [DIRECTORY_SHELL_KEY, DIRECTORY_BACKGROUND_SHELL_KEY]
            .iter()
            .any(|key| self.registry.key_exists(Hive::CurrentUser, key))
    }

    fn has_machine_registration(&self) -> bool {
        self.registry.key_exists(Hive::LocalMachine, DIRECTORY_SHELL_KEY)
            || self
                .registry
                .key_exists(Hive::LocalMachine, DIRECTORY_BACKGROUND_SHELL_KEY)
    }

    fn has_active_shell_key(&self, hive: Hive, key: &str) -> bool {
        if !self.registry.key_exists(hive, key) {
            return false;
        }
        if hive == Hive::CurrentUser && self.is_suppression_key(hive, key) {
            return false;
        }
        self.registry
            .read_string(hive, &format!("{key}\\command"), "")
            .is_some_and(|c| !c.trim().is_empty())
    }

    fn is_hive_fully_registered(&self, hive: Hive) -> bool {
        self.has_active_shell_key(hive, DIRECTORY_SHELL_KEY)
            && self.has_active_shell_key(hive, DIRECTORY_BACKGROUND_SHELL_KEY)
    }

    /// Both verbs active in HKCU or HKLM and not hidden for this user.
    pub fn is_registered(&self) -> bool {
        if !self.supported || self.is_user_suppressed() {
            return false;
        }
        self.is_hive_fully_registered(Hive::CurrentUser)
            || self.is_hive_fully_registered(Hive::LocalMachine)
    }

    /// Any single runnable verb (a partial leftover still counts).
    pub fn has_any_active_verb(&self) -> bool {
        if !self.supported || self.is_user_suppressed() {
            return false;
        }
        [Hive::CurrentUser, Hive::LocalMachine].iter().any(|hive| {
            self.has_active_shell_key(*hive, DIRECTORY_SHELL_KEY)
                || self.has_active_shell_key(*hive, DIRECTORY_BACKGROUND_SHELL_KEY)
        })
    }

    /// Disable for this user: never deletes HKLM verbs (other accounts and
    /// the uninstaller own them); hides them per user instead.
    pub fn remove(&self) -> ExplorerResult {
        if !self.supported {
            return ExplorerResult::unsupported();
        }
        let mut success = true;
        if self.has_machine_registration() {
            if !self.write_user_suppression() {
                success = false;
            }
        } else {
            for key in [DIRECTORY_SHELL_KEY, DIRECTORY_BACKGROUND_SHELL_KEY] {
                if !self.delete_key_checked(Hive::CurrentUser, key)
                    && self.registry.key_exists(Hive::CurrentUser, key)
                {
                    success = false;
                }
            }
        }
        let still_active = self.has_any_active_verb();
        ExplorerResult {
            success: success && !still_active,
            enabled: still_active,
            supported: true,
        }
    }

    /// Enable: refresh HKLM verbs when a machine install exists (before
    /// touching working HKCU verbs), else write per-user verbs.
    pub fn install(&self, spec: &LaunchSpec) -> ExplorerResult {
        if !self.supported {
            return ExplorerResult::unsupported();
        }
        let exe = spec.executable_path.trim();
        if exe.is_empty() {
            return ExplorerResult {
                success: false,
                enabled: false,
                supported: true,
            };
        }
        let app_args = normalize_args(&spec.app_args);
        let was_suppressed = self.is_user_suppressed();
        let machine_registered = self.has_machine_registration();
        let folder = VerbSpec {
            executable_path: exe,
            placeholder: "%1",
            app_args: &app_args,
        };
        let background = VerbSpec {
            executable_path: exe,
            placeholder: "%V",
            app_args: &app_args,
        };

        if machine_registered {
            let mut writes_ok = true;
            for (key, verb) in [(DIRECTORY_SHELL_KEY, &folder), (DIRECTORY_BACKGROUND_SHELL_KEY, &background)] {
                if !self.write_verb(Hive::LocalMachine, key, verb) {
                    writes_ok = false;
                }
            }
            let machine_current = self.verb_is_current(Hive::LocalMachine, DIRECTORY_SHELL_KEY, &folder)
                && self.verb_is_current(Hive::LocalMachine, DIRECTORY_BACKGROUND_SHELL_KEY, &background);
            if machine_current {
                let cleared = self.clear_user_shell_keys() && !self.has_residual_user_shell_keys();
                if !cleared {
                    if was_suppressed {
                        self.write_user_suppression();
                    }
                    return ExplorerResult {
                        success: false,
                        enabled: self.has_any_active_verb(),
                        supported: true,
                    };
                }
                return ExplorerResult {
                    success: writes_ok || machine_current,
                    enabled: true,
                    supported: true,
                };
            }
            // Stale / partial HKLM verbs that cannot be repaired unelevated:
            // fall through to a per-user registration, which wins for this user.
        }

        let suppression_cleared = self.clear_user_suppression();
        let mut writes_ok = true;
        for (key, verb) in [(DIRECTORY_SHELL_KEY, &folder), (DIRECTORY_BACKGROUND_SHELL_KEY, &background)] {
            if !self.write_verb(Hive::CurrentUser, key, verb) {
                writes_ok = false;
            }
        }
        let user_current = self.verb_is_current(Hive::CurrentUser, DIRECTORY_SHELL_KEY, &folder)
            && self.verb_is_current(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY, &background);
        let success = suppression_cleared && (writes_ok || user_current);
        if !success && was_suppressed {
            self.write_user_suppression();
        }
        let enabled = success || self.has_any_active_verb();
        ExplorerResult {
            success,
            enabled,
            supported: true,
        }
    }

    pub fn apply(&self, enabled: bool, spec: &LaunchSpec) -> ExplorerResult {
        if !self.supported {
            return ExplorerResult::unsupported();
        }
        if enabled {
            self.install(spec)
        } else {
            self.remove()
        }
    }

    /// The toggle state shown at startup before [`Self::apply_initial`] ran
    /// (saved preference first, else the live registry).
    pub fn resolve_enabled(&self) -> (bool, bool) {
        if !self.supported {
            return (false, false);
        }
        if let Some(preferred) = self.read_enabled_preference() {
            return (preferred, true);
        }
        if self.probe_current() {
            return (self.has_any_active_verb(), true);
        }
        (self.is_registered() || self.has_any_active_verb(), true)
    }

    /// Startup reconciliation (Electron `applyInitialExplorerContextMenuPreference`).
    pub fn apply_initial(&self, spec: &LaunchSpec) -> ExplorerResult {
        if !self.supported {
            return ExplorerResult::unsupported();
        }
        let record = self.read_preference();
        let current_exe = spec.executable_path.trim().to_owned();
        let app_args = normalize_args(&spec.app_args);
        let current_spec = LaunchSpec {
            executable_path: current_exe.clone(),
            app_args: app_args.clone(),
        };

        let Some(record) = record else {
            // No user choice: keep installer / portable state, repairing any
            // residual verb (complete or partial) so the toggle can see it.
            let residual = self.is_registered() || self.has_any_active_verb();
            if residual {
                let refreshed = self.install(&current_spec);
                if refreshed.success && refreshed.enabled {
                    self.write_enabled_preference(true, &current_spec);
                }
                return ExplorerResult {
                    enabled: refreshed.enabled || self.has_any_active_verb(),
                    success: refreshed.success,
                    supported: true,
                };
            }
            // Default off: a probe marker only, never a durable "disabled".
            self.write_probe_marker();
            return ExplorerResult {
                enabled: false,
                success: true,
                supported: true,
            };
        };

        let preferred = record.enabled;
        let schema_current = record.schema_version == EXPLORER_CONTEXT_MENU_SCHEMA_VERSION;
        let executable_current =
            !preferred || current_exe.is_empty() || record.executable_path == current_exe;
        let args_current = !preferred || normalize_args(&record.app_args) == app_args;

        // Healthy warm start; a disabled preference is always re-asserted
        // (installer updates re-create the verbs).
        if preferred && schema_current && executable_current && args_current && self.is_registered() {
            return ExplorerResult {
                enabled: true,
                success: true,
                supported: true,
            };
        }

        let applied = self.apply(preferred, &current_spec);
        if applied.success {
            self.write_enabled_preference(preferred, &current_spec);
        }
        ExplorerResult {
            enabled: if applied.success { preferred } else { applied.enabled },
            success: applied.success,
            supported: true,
        }
    }
}

/// Electron `updateExplorerContextMenuEnabledPreference`: apply, persist,
/// and restore the previous state when either step fails.
pub fn update_enabled_preference(
    current: bool,
    requested: bool,
    mut apply: impl FnMut(bool) -> ExplorerResult,
    write: impl FnOnce(bool) -> bool,
) -> ExplorerResult {
    if requested == current {
        return ExplorerResult {
            enabled: current,
            success: true,
            supported: true,
        };
    }
    let applied = apply(requested);
    if !applied.success {
        let rolled_back = apply(current);
        return ExplorerResult {
            enabled: rolled_back.enabled,
            success: false,
            supported: applied.supported,
        };
    }
    if !write(requested) {
        let rolled_back = apply(current);
        return ExplorerResult {
            enabled: rolled_back.enabled,
            success: false,
            supported: true,
        };
    }
    ExplorerResult {
        enabled: requested,
        success: true,
        supported: true,
    }
}

// ---------------------------------------------------------------------------
// Real Windows registry
// ---------------------------------------------------------------------------

/// HKCU / HKLM through `windows-registry`.
#[cfg(windows)]
pub struct WindowsRegistry;

#[cfg(windows)]
impl WindowsRegistry {
    fn root(hive: Hive) -> &'static windows_registry::Key {
        match hive {
            Hive::CurrentUser => windows_registry::CURRENT_USER,
            Hive::LocalMachine => windows_registry::LOCAL_MACHINE,
        }
    }
}

#[cfg(windows)]
impl Registry for WindowsRegistry {
    fn key_exists(&self, hive: Hive, path: &str) -> bool {
        Self::root(hive).open(path).is_ok()
    }

    fn value_exists(&self, hive: Hive, path: &str, name: &str) -> bool {
        Self::root(hive)
            .open(path)
            .is_ok_and(|key| key.get_type(name).is_ok())
    }

    fn read_string(&self, hive: Hive, path: &str, name: &str) -> Option<String> {
        Self::root(hive).open(path).ok()?.get_string(name).ok()
    }

    fn write_string(&self, hive: Hive, path: &str, name: &str, value: &str) -> bool {
        Self::root(hive)
            .create(path)
            .and_then(|key| key.set_string(name, value))
            .is_ok()
    }

    fn delete_key(&self, hive: Hive, path: &str) -> bool {
        Self::root(hive).remove_tree(path).is_ok() || !self.key_exists(hive, path)
    }

    fn delete_value(&self, hive: Hive, path: &str, name: &str) -> bool {
        Self::root(hive)
            .create(path)
            .and_then(|key| key.remove_value(name))
            .is_ok()
    }
}

// ---------------------------------------------------------------------------
// In-memory registry (tests)
// ---------------------------------------------------------------------------

/// Case-insensitive in-memory registry. `read_only` hives reject writes and
/// deletes (an unelevated process and HKLM).
#[derive(Default)]
pub struct MemoryRegistry {
    keys: std::sync::Mutex<std::collections::BTreeMap<(Hive, String), std::collections::BTreeMap<String, String>>>,
    pub read_only: std::sync::Mutex<std::collections::BTreeSet<Hive>>,
    pub writes: std::sync::atomic::AtomicUsize,
}

impl MemoryRegistry {
    fn norm(path: &str) -> String {
        path.to_ascii_lowercase()
    }

    pub fn set(&self, hive: Hive, path: &str, name: &str, value: &str) {
        let mut keys = self.keys.lock().unwrap();
        let mut prefix = String::new();
        for part in Self::norm(path).split('\\') {
            if !prefix.is_empty() {
                prefix.push('\\');
            }
            prefix.push_str(part);
            keys.entry((hive, prefix.clone())).or_default();
        }
        keys.entry((hive, Self::norm(path)))
            .or_default()
            .insert(name.to_ascii_lowercase(), value.to_owned());
    }

    pub fn get(&self, hive: Hive, path: &str, name: &str) -> Option<String> {
        self.keys
            .lock()
            .unwrap()
            .get(&(hive, Self::norm(path)))?
            .get(&name.to_ascii_lowercase())
            .cloned()
    }

    fn writable(&self, hive: Hive) -> bool {
        !self.read_only.lock().unwrap().contains(&hive)
    }
}

impl Registry for MemoryRegistry {
    fn key_exists(&self, hive: Hive, path: &str) -> bool {
        self.keys.lock().unwrap().contains_key(&(hive, Self::norm(path)))
    }

    fn value_exists(&self, hive: Hive, path: &str, name: &str) -> bool {
        self.get(hive, path, name).is_some()
    }

    fn read_string(&self, hive: Hive, path: &str, name: &str) -> Option<String> {
        self.get(hive, path, name)
    }

    fn write_string(&self, hive: Hive, path: &str, name: &str, value: &str) -> bool {
        if !self.writable(hive) {
            return false;
        }
        self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.set(hive, path, name, value);
        true
    }

    fn delete_key(&self, hive: Hive, path: &str) -> bool {
        if !self.writable(hive) {
            return false;
        }
        let norm = Self::norm(path);
        let child_prefix = format!("{norm}\\");
        self.keys
            .lock()
            .unwrap()
            .retain(|(h, p), _| !(*h == hive && (*p == norm || p.starts_with(&child_prefix))));
        true
    }

    fn delete_value(&self, hive: Hive, path: &str, name: &str) -> bool {
        if !self.writable(hive) {
            return false;
        }
        if let Some(values) = self.keys.lock().unwrap().get_mut(&(hive, Self::norm(path))) {
            values.remove(&name.to_ascii_lowercase());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "C:\\Apps\\Netcatty.exe";

    fn spec(exe: &str) -> LaunchSpec {
        LaunchSpec {
            executable_path: exe.to_owned(),
            app_args: Vec::new(),
        }
    }

    fn install_verbs(reg: &MemoryRegistry, hive: Hive, exe: &str) {
        for (key, placeholder) in [(DIRECTORY_SHELL_KEY, "%1"), (DIRECTORY_BACKGROUND_SHELL_KEY, "%V")] {
            reg.set(hive, key, "MUIVerb", MENU_LABEL);
            reg.set(hive, key, "Icon", &format!("{exe},0"));
            reg.set(hive, &format!("{key}\\command"), "", &build_command(exe, placeholder, &[]).unwrap());
        }
    }

    fn ctx<'a>(reg: &'a MemoryRegistry, dir: &'a Path) -> ExplorerContextMenu<'a> {
        ExplorerContextMenu {
            registry: reg,
            data_dir: dir,
            supported: true,
        }
    }

    #[test]
    fn command_line_matches_electron_and_the_installer() {
        assert_eq!(
            build_command("C:\\Program Files\\Netcatty\\Netcatty.exe", "%1", &[]).unwrap(),
            "\"C:\\Program Files\\Netcatty\\Netcatty.exe\" -- --open-terminal-path=\"%1.\""
        );
        assert_eq!(
            build_command("C:\\Netcatty\\Netcatty.exe", "%V", &[]).unwrap(),
            "\"C:\\Netcatty\\Netcatty.exe\" -- --open-terminal-path=\"%V.\""
        );
        assert_eq!(
            build_command("C:\\dev\\electron.exe", "%1", &["C:\\dev\\netcatty".to_owned()]).unwrap(),
            "\"C:\\dev\\electron.exe\" \"C:\\dev\\netcatty\" -- --open-terminal-path=\"%1.\""
        );
        assert!(build_command("", "%1", &[]).is_none());
    }

    #[test]
    fn registration_requires_both_verbs_with_commands() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::CurrentUser, EXE);
        assert!(ctx(&reg, dir.path()).is_registered());
        reg.delete_key(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY);
        assert!(!ctx(&reg, dir.path()).is_registered());
        assert!(ctx(&reg, dir.path()).has_any_active_verb());

        let bare = MemoryRegistry::default();
        bare.set(Hive::CurrentUser, DIRECTORY_SHELL_KEY, "MUIVerb", MENU_LABEL);
        assert!(!ctx(&bare, dir.path()).is_registered());
        assert!(!ctx(&bare, dir.path()).has_any_active_verb());
    }

    #[test]
    fn user_suppression_hides_machine_verbs() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::LocalMachine, EXE);
        assert!(ctx(&reg, dir.path()).is_registered());
        reg.set(Hive::CurrentUser, DIRECTORY_SHELL_KEY, SUPPRESSION_VALUE, "");
        // Only one verb hidden: still registered.
        assert!(ctx(&reg, dir.path()).is_registered());
        reg.set(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY, SUPPRESSION_VALUE, "");
        assert!(!ctx(&reg, dir.path()).is_registered());
    }

    #[test]
    fn remove_deletes_per_user_keys() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::CurrentUser, EXE);
        let result = ctx(&reg, dir.path()).remove();
        assert_eq!(result, ExplorerResult { success: true, enabled: false, supported: true });
        assert!(!reg.key_exists(Hive::CurrentUser, DIRECTORY_SHELL_KEY));
        assert!(!reg.key_exists(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY));
    }

    #[test]
    fn remove_never_deletes_hklm_and_suppresses_instead() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::LocalMachine, EXE);
        reg.read_only.lock().unwrap().insert(Hive::LocalMachine);
        let result = ctx(&reg, dir.path()).remove();
        assert_eq!(result, ExplorerResult { success: true, enabled: false, supported: true });
        assert!(reg.value_exists(Hive::CurrentUser, DIRECTORY_SHELL_KEY, SUPPRESSION_VALUE));
        assert!(reg.value_exists(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY, SUPPRESSION_VALUE));
        assert!(reg.key_exists(Hive::LocalMachine, DIRECTORY_SHELL_KEY));
    }

    #[test]
    fn suppression_rollback_keeps_portable_commands() {
        // HKCU folder verb is a working portable install; the background
        // suppression write fails (simulated by a read-only HKCU after the
        // first write is impossible here, so emulate with a custom registry).
        struct FailBackground(MemoryRegistry);
        impl Registry for FailBackground {
            fn key_exists(&self, h: Hive, p: &str) -> bool { self.0.key_exists(h, p) }
            fn value_exists(&self, h: Hive, p: &str, n: &str) -> bool { self.0.value_exists(h, p, n) }
            fn read_string(&self, h: Hive, p: &str, n: &str) -> Option<String> { self.0.read_string(h, p, n) }
            fn write_string(&self, h: Hive, p: &str, n: &str, v: &str) -> bool {
                if p == DIRECTORY_BACKGROUND_SHELL_KEY && n == SUPPRESSION_VALUE {
                    return false;
                }
                self.0.write_string(h, p, n, v)
            }
            fn delete_key(&self, h: Hive, p: &str) -> bool { self.0.delete_key(h, p) }
            fn delete_value(&self, h: Hive, p: &str, n: &str) -> bool { self.0.delete_value(h, p, n) }
        }
        let dir = tempfile::tempdir().unwrap();
        let reg = FailBackground(MemoryRegistry::default());
        install_verbs(&reg.0, Hive::LocalMachine, EXE);
        install_verbs(&reg.0, Hive::CurrentUser, "D:\\Portable\\Netcatty.exe");
        let menu = ExplorerContextMenu { registry: &reg, data_dir: dir.path(), supported: true };
        let result = menu.remove();
        assert!(!result.success);
        assert!(result.enabled);
        // The portable command survived and is not hidden.
        assert!(reg.0.get(Hive::CurrentUser, &format!("{DIRECTORY_SHELL_KEY}\\command"), "").is_some());
        assert!(!reg.0.value_exists(Hive::CurrentUser, DIRECTORY_SHELL_KEY, SUPPRESSION_VALUE));
    }

    #[test]
    fn install_writes_hkcu_verbs() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        let result = ctx(&reg, dir.path()).install(&spec(EXE));
        assert_eq!(result, ExplorerResult { success: true, enabled: true, supported: true });
        assert_eq!(
            reg.get(Hive::CurrentUser, &format!("{DIRECTORY_BACKGROUND_SHELL_KEY}\\command"), "").unwrap(),
            "\"C:\\Apps\\Netcatty.exe\" -- --open-terminal-path=\"%V.\""
        );
        assert_eq!(reg.get(Hive::CurrentUser, DIRECTORY_SHELL_KEY, "MUIVerb").unwrap(), MENU_LABEL);
        assert_eq!(reg.get(Hive::CurrentUser, DIRECTORY_SHELL_KEY, "Icon").unwrap(), "C:\\Apps\\Netcatty.exe,0");
    }

    #[test]
    fn install_skips_writes_when_current() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::CurrentUser, EXE);
        let before = reg.writes.load(std::sync::atomic::Ordering::SeqCst);
        assert!(ctx(&reg, dir.path()).install(&spec(EXE)).success);
        assert_eq!(reg.writes.load(std::sync::atomic::Ordering::SeqCst), before);
    }

    #[test]
    fn install_refreshes_hklm_without_duplicating_into_hkcu() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::LocalMachine, EXE);
        install_verbs(&reg, Hive::CurrentUser, "D:\\Old\\Netcatty.exe");
        let result = ctx(&reg, dir.path()).install(&spec(EXE));
        assert_eq!(result, ExplorerResult { success: true, enabled: true, supported: true });
        assert!(!reg.key_exists(Hive::CurrentUser, DIRECTORY_SHELL_KEY));
        assert!(!reg.key_exists(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY));
    }

    #[test]
    fn install_falls_back_to_hkcu_when_hklm_is_stale_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::LocalMachine, "C:\\Old\\Netcatty.exe");
        reg.read_only.lock().unwrap().insert(Hive::LocalMachine);
        let result = ctx(&reg, dir.path()).install(&spec(EXE));
        assert_eq!(result, ExplorerResult { success: true, enabled: true, supported: true });
        assert!(ctx(&reg, dir.path()).verb_is_current(
            Hive::CurrentUser,
            DIRECTORY_SHELL_KEY,
            &VerbSpec { executable_path: EXE, placeholder: "%1", app_args: &[] }
        ));
    }

    #[test]
    fn install_unsuppresses_and_reports_failure_when_cleanup_fails() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::LocalMachine, EXE);
        reg.set(Hive::CurrentUser, DIRECTORY_SHELL_KEY, SUPPRESSION_VALUE, "");
        reg.set(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY, SUPPRESSION_VALUE, "");
        // HKLM is current: clearing the HKCU hides re-enables the machine verbs.
        let result = ctx(&reg, dir.path()).install(&spec(EXE));
        assert_eq!(result, ExplorerResult { success: true, enabled: true, supported: true });
        assert!(ctx(&reg, dir.path()).is_registered());

        // With HKCU read-only the residual suppression cannot be cleared.
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::LocalMachine, EXE);
        reg.set(Hive::CurrentUser, DIRECTORY_SHELL_KEY, SUPPRESSION_VALUE, "");
        reg.set(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY, SUPPRESSION_VALUE, "");
        reg.read_only.lock().unwrap().insert(Hive::CurrentUser);
        let result = ctx(&reg, dir.path()).install(&spec(EXE));
        assert!(!result.success);
        assert!(!result.enabled);
    }

    #[test]
    fn update_rolls_back_on_failures() {
        let mut applied = Vec::new();
        let result = update_enabled_preference(
            false,
            true,
            |v| {
                applied.push(v);
                ExplorerResult { success: true, enabled: v, supported: true }
            },
            |_| false,
        );
        assert_eq!(result, ExplorerResult { success: false, enabled: false, supported: true });
        assert_eq!(applied, vec![true, false]);

        let mut applied = Vec::new();
        let result = update_enabled_preference(
            true,
            false,
            |v| {
                applied.push(v);
                ExplorerResult { success: v, enabled: true, supported: true }
            },
            |_| true,
        );
        assert_eq!(result, ExplorerResult { success: false, enabled: true, supported: true });
        assert_eq!(applied, vec![false, true]);
    }

    #[test]
    fn saved_preference_wins_over_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        install_verbs(&reg, Hive::CurrentUser, EXE);
        let menu = ctx(&reg, dir.path());
        assert_eq!(menu.resolve_enabled(), (true, true));
        assert!(menu.write_enabled_preference(false, &spec(EXE)));
        assert_eq!(menu.resolve_enabled(), (false, true));
    }

    #[test]
    fn initial_default_off_writes_only_a_probe_marker() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        let menu = ctx(&reg, dir.path());
        assert_eq!(menu.apply_initial(&spec(EXE)), ExplorerResult { success: true, enabled: false, supported: true });
        assert!(dir.path().join(EXPLORER_CONTEXT_MENU_PROBE_FILE).exists());
        assert!(!dir.path().join(EXPLORER_CONTEXT_MENU_PREFERENCES_FILE).exists());
        // A later per-user install is still repaired and adopted.
        install_verbs(&reg, Hive::CurrentUser, "C:\\Other\\Netcatty.exe");
        let result = menu.apply_initial(&spec(EXE));
        assert_eq!(result, ExplorerResult { success: true, enabled: true, supported: true });
        assert_eq!(menu.read_enabled_preference(), Some(true));
        assert_eq!(
            reg.get(Hive::CurrentUser, DIRECTORY_SHELL_KEY, "Icon").unwrap(),
            "C:\\Apps\\Netcatty.exe,0"
        );
    }

    #[test]
    fn initial_warm_start_and_reapply_cases() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        let menu = ctx(&reg, dir.path());
        install_verbs(&reg, Hive::CurrentUser, EXE);
        menu.write_enabled_preference(true, &spec(EXE));
        let before = reg.writes.load(std::sync::atomic::Ordering::SeqCst);
        assert!(menu.apply_initial(&spec(EXE)).enabled);
        assert_eq!(reg.writes.load(std::sync::atomic::Ordering::SeqCst), before, "warm start is write-free");

        // A missing verb is re-applied.
        reg.delete_key(Hive::CurrentUser, DIRECTORY_BACKGROUND_SHELL_KEY);
        assert!(menu.apply_initial(&spec(EXE)).enabled);
        assert!(menu.is_registered());

        // The portable executable moved: verbs follow it.
        let moved = "E:\\Usb\\Netcatty.exe";
        assert!(menu.apply_initial(&spec(moved)).enabled);
        assert_eq!(reg.get(Hive::CurrentUser, DIRECTORY_SHELL_KEY, "Icon").unwrap(), format!("{moved},0"));

        // A disabled preference re-suppresses installer verbs every launch.
        install_verbs(&reg, Hive::LocalMachine, moved);
        reg.read_only.lock().unwrap().insert(Hive::LocalMachine);
        menu.write_enabled_preference(false, &spec(moved));
        let result = menu.apply_initial(&spec(moved));
        assert_eq!(result, ExplorerResult { success: true, enabled: false, supported: true });
        assert!(!menu.is_registered());
    }

    #[test]
    fn unsupported_platforms_report_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let reg = MemoryRegistry::default();
        let menu = ExplorerContextMenu { registry: &reg, data_dir: dir.path(), supported: false };
        assert_eq!(menu.apply(true, &spec(EXE)), ExplorerResult { success: true, enabled: false, supported: false });
        assert_eq!(menu.resolve_enabled(), (false, false));
    }

    #[test]
    fn portable_launcher_path_wins() {
        assert_eq!(
            resolve_launch_spec(Some("D:\\Portable\\Netcatty.exe"), Path::new("C:\\Temp\\x\\Netcatty.exe")).executable_path,
            "D:\\Portable\\Netcatty.exe"
        );
        assert_eq!(
            resolve_launch_spec(Some("  "), Path::new("C:\\Apps\\Netcatty.exe")).executable_path,
            "C:\\Apps\\Netcatty.exe"
        );
    }
}
