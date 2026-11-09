//! Host compatibility and runtime placement policy (ports of
//! `packages/plugin-cli/src/compatibility.ts` and
//! `domain/pluginRuntimePolicy.cjs`).

use super::semver_util::{satisfies, valid_range, valid_version};
use crate::error::PluginError;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

const DEFAULT_PLUGIN_API_VERSION: &str = "0.1.0-internal.1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Compatibility {
    pub compatible: bool,
    pub api_version: String,
    pub enabled_features: Vec<String>,
    pub missing_required_features: Vec<String>,
    pub errors: Vec<String>,
}

fn check_engine(label: &str, version: &str, range: &str, errors: &mut Vec<String>) {
    if !valid_version(version) {
        errors.push(format!("Host {label} version is not valid semver: {version}"));
    } else if !valid_range(range) {
        errors.push(format!("Plugin {label} range is not valid semver: {range}"));
    } else if !satisfies(version, range) {
        errors.push(format!("Host {label} version {version} does not satisfy {range}"));
    }
}

/// `checkPluginCompatibility`.
pub fn check_compatibility(
    manifest: &Value,
    netcatty_version: &str,
    api_version: Option<&str>,
    features: &[String],
) -> Compatibility {
    let engines = manifest.get("engines").cloned().unwrap_or(Value::Null);
    let api_range = engines.get("api").and_then(Value::as_str).unwrap_or("");
    let mut api = api_version.unwrap_or(DEFAULT_PLUGIN_API_VERSION).to_string();
    // Legacy packages keep negotiating the previous, unchanged wire revision.
    if api == DEFAULT_PLUGIN_API_VERSION
        && manifest.get("icon").is_none()
        && !satisfies(&api, api_range)
        && satisfies("0.1.0-internal", api_range)
    {
        api = "0.1.0-internal".into();
    }
    let mut errors = Vec::new();
    check_engine(
        "Netcatty",
        netcatty_version,
        engines.get("netcatty").and_then(Value::as_str).unwrap_or(""),
        &mut errors,
    );
    check_engine("plugin API", &api, api_range, &mut errors);
    let supported: HashSet<&str> = features.iter().map(String::as_str).collect();
    let list = |key: &str| -> Vec<String> {
        manifest
            .get("features")
            .and_then(|f| f.get(key))
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };
    let required = list("required");
    let optional = list("optional");
    let mut missing: Vec<String> = required.iter().filter(|f| !supported.contains(f.as_str())).cloned().collect();
    missing.sort();
    if !missing.is_empty() {
        errors.push(format!("Missing required features: {}", missing.join(", ")));
    }
    let mut enabled: Vec<String> = required
        .iter()
        .chain(optional.iter())
        .filter(|f| supported.contains(f.as_str()))
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    enabled.sort();
    Compatibility {
        compatible: errors.is_empty(),
        api_version: api,
        enabled_features: enabled,
        missing_required_features: missing,
        errors,
    }
}

/// `isStaticThemePack`.
pub fn is_static_theme_pack(manifest: &Value) -> bool {
    let main = manifest.get("main").and_then(Value::as_object);
    let contributes = manifest.get("contributes").and_then(Value::as_object);
    main.is_some_and(|m| m.get("data").and_then(Value::as_str) == Some("theme") && m.len() == 1)
        && contributes.is_some_and(|c| {
            c.get("themes").and_then(Value::as_array).is_some_and(|t| !t.is_empty())
                && c.keys().all(|k| k == "themes")
        })
        && manifest
            .get("permissions")
            .and_then(Value::as_object)
            .is_none_or(|p| p.is_empty())
        && manifest
            .get("activationEvents")
            .and_then(Value::as_array)
            .is_none_or(|a| a.is_empty())
        && manifest
            .get("companionExecutables")
            .and_then(Value::as_array)
            .is_none_or(|a| a.is_empty())
        && manifest
            .get("features")
            .and_then(|f| f.get("required"))
            .and_then(Value::as_array)
            .is_some_and(|r| r.iter().any(|f| f == "appearance.theme-packs"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeKind {
    Browser,
    Utility,
    Data,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Utility => "utility",
            Self::Data => "data",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeDescription {
    pub default_kind: RuntimeKind,
    pub data_only: bool,
    pub has_node: bool,
    pub declares_advanced: bool,
    pub browser_only: bool,
}

/// `describePluginRuntime`.
pub fn describe_runtime(manifest: &Value) -> RuntimeDescription {
    let providers = manifest
        .get("contributes")
        .and_then(|c| c.get("providers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let permissions: Vec<String> = ["required", "optional"]
        .iter()
        .flat_map(|k| {
            manifest
                .get("permissions")
                .and_then(|p| p.get(*k))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|p| super::manifest::permission_name(&p).map(str::to_string))
        .collect();
    let has_companions = manifest
        .get("companionExecutables")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    let has_interceptors = providers.iter().any(|p| {
        matches!(
            p.get("kind").and_then(Value::as_str),
            Some("terminal.interceptor.input" | "terminal.interceptor.output")
        )
    });
    let declares_advanced = permissions.iter().any(|p| {
        matches!(
            p.as_str(),
            "runtime.advanced" | "companion.execute" | "terminal.intercept.input" | "terminal.intercept.output"
        )
    });
    let main = manifest.get("main");
    let has_browser = main.and_then(|m| m.get("browser")).is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()));
    let has_node = main.and_then(|m| m.get("node")).is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()));
    let has_data = main.and_then(|m| m.get("data")).is_some();
    let data_only = is_static_theme_pack(manifest);
    let default_kind = if data_only {
        RuntimeKind::Data
    } else if has_browser && !has_companions && !has_interceptors {
        RuntimeKind::Browser
    } else {
        RuntimeKind::Utility
    };
    RuntimeDescription {
        default_kind,
        data_only,
        has_node,
        declares_advanced,
        browser_only: !has_data && has_browser && !has_node && !has_companions && !has_interceptors && !declares_advanced,
    }
}

/// `assertBrowserOnlyPlugin` (code `PLUGIN_UNSUPPORTED_RUNTIME`).
pub fn assert_browser_only(manifest: &Value) -> Result<(), PluginError> {
    if !describe_runtime(manifest).browser_only && !is_static_theme_pack(manifest) {
        return Err(PluginError::host(
            "This package requires advanced developer mode; normal plugin management accepts browser-only packages",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_policy() {
        let browser = json!({ "main": { "browser": "a.js" } });
        assert!(describe_runtime(&browser).browser_only);
        let node = json!({ "main": { "node": "a.js" }, "permissions": { "required": ["runtime.advanced"] } });
        assert!(assert_browser_only(&node).is_err());
        assert_eq!(describe_runtime(&node).default_kind, RuntimeKind::Utility);
    }
}
