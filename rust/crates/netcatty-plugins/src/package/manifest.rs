//! Manifest validation (port of `packages/plugin-cli/src/manifest.ts`):
//! JSON structure limits, schema validation against `PluginManifest` and the
//! semantic checks the schema cannot express.

use super::path::assert_safe_package_path;
use super::semver_util::{satisfies, valid_range, valid_version};
use crate::contract;
use crate::error::{PluginError, PluginResult};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

const MAX_SETTING_PATTERN_LENGTH: usize = 512;
const MAX_RESTRICTED_SCHEMA_DEPTH: usize = 8;
const MAX_RESTRICTED_SCHEMA_NODES: usize = 256;
const RESTRICTED_SCHEMA_TYPES: &[&str] = &["array", "boolean", "integer", "null", "number", "object", "string"];
const RESTRICTED_SCHEMA_KEYWORDS: &[&str] = &[
    "additionalProperties", "const", "enum", "items", "maxItems", "maxLength", "maximum",
    "minItems", "minLength", "minimum", "properties", "required", "type",
];

/// Result of [`validate_manifest_value`].
pub struct ManifestValidation {
    pub manifest: Option<Value>,
    pub errors: Vec<String>,
}

fn s<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn arr<'a>(value: Option<&'a Value>) -> &'a [Value] {
    value.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn contributes<'a>(manifest: &'a Value, key: &str) -> &'a [Value] {
    arr(manifest.get("contributes").and_then(|c| c.get(key)))
}

pub fn permission_name(declaration: &Value) -> Option<&str> {
    declaration
        .as_str()
        .or_else(|| declaration.get("permission").and_then(Value::as_str))
}

/// Package icon paths of an `IconReference`.
pub fn package_icon_paths(icon: Option<&Value>) -> Vec<String> {
    let Some(icon) = icon else { return Vec::new() };
    if s(icon, "kind") != Some("package") {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(light) = s(icon, "light") {
        out.push(light.to_string());
    }
    if let Some(dark) = s(icon, "dark") {
        out.push(dark.to_string());
    }
    out
}

/// Every package file a manifest references (icons, entrypoints, themes,
/// contribution icons). Companion paths are listed separately.
pub fn referenced_paths(manifest: &Value) -> Vec<String> {
    let mut out = package_icon_paths(manifest.get("icon"));
    if let Some(main) = manifest.get("main") {
        for key in ["browser", "node"] {
            if let Some(path) = s(main, key) {
                out.push(path.to_string());
            }
        }
    }
    for theme in contributes(manifest, "themes") {
        if let Some(entry) = s(theme, "entry") {
            out.push(entry.to_string());
        }
    }
    for group in ["commands", "menus", "views"] {
        for item in contributes(manifest, group) {
            out.extend(package_icon_paths(item.get("icon")));
        }
    }
    out
}

/// `(path, sha256)` of every declared companion variant.
pub fn companion_variants(manifest: &Value) -> Vec<(String, String)> {
    arr(manifest.get("companionExecutables"))
        .iter()
        .flat_map(|companion| arr(companion.get("variants")).iter())
        .filter_map(|variant| Some((s(variant, "path")?.to_string(), s(variant, "sha256")?.to_string())))
        .collect()
}

fn assert_manifest_json_structure(root: &Value) -> Result<(), String> {
    let limits = contract::def_const("JsonValueLimits");
    let max_depth = limits
        .and_then(|l| l.get("maxDepth"))
        .and_then(Value::as_u64)
        .unwrap_or(64) as usize;
    let max_nodes = limits
        .and_then(|l| l.get("maxNodes"))
        .and_then(Value::as_u64)
        .unwrap_or(10_000) as usize;
    let mut stack = vec![(root, 0usize)];
    let mut nodes = 0;
    while let Some((value, depth)) = stack.pop() {
        if depth > max_depth {
            return Err(format!("JSON values must not exceed {max_depth} levels of nesting"));
        }
        nodes += 1;
        if nodes > max_nodes {
            return Err(format!("JSON values must not contain more than {max_nodes} nodes"));
        }
        match value {
            Value::Array(items) => items.iter().rev().for_each(|v| stack.push((v, depth + 1))),
            Value::Object(map) => map.values().rev().for_each(|v| stack.push((v, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

fn resource_scoped_permissions() -> HashSet<String> {
    contract::schema()["$defs"]["ResourceScopedPermission"]["enum"]
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

fn validate_required_permission_bounds(value: &Value) -> Vec<String> {
    let scoped = resource_scoped_permissions();
    let Some(required) = value
        .get("permissions")
        .and_then(|p| p.get("required"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut errors = Vec::new();
    for declaration in required {
        if let Some(name) = declaration.as_str() {
            if scoped.contains(name) {
                errors.push(format!("Required permission {name} must declare explicit resources"));
            }
        } else if let (Some(name), Some(resources)) = (
            declaration.get("permission").and_then(Value::as_str),
            declaration.get("resources").and_then(Value::as_array),
        ) {
            if scoped.contains(name) && resources.iter().any(|r| r == "*") {
                errors.push(format!("Required permission {name} must not use the wildcard resource"));
            }
        }
    }
    errors
}

fn permission_resource_limit(permission: &str) -> usize {
    match permission {
        "filesystem.read" | "filesystem.write" => 8_192,
        "companion.execute" => 192,
        _ => 2_048,
    }
}

fn declarations(manifest: &Value, kind: &str) -> Vec<Value> {
    arr(manifest.get("permissions").and_then(|p| p.get(kind))).to_vec()
}

/// `settingPatternError`: rejects lookarounds, backreferences and
/// quantified groups (ReDoS-prone features), then compiles as an ECMAScript
/// `u` regex.
pub fn setting_pattern_error(source: &str) -> Option<&'static str> {
    let len = source.encode_utf16().count();
    let quantified_group = {
        let bytes = source.as_bytes();
        let mut found = false;
        for (index, b) in bytes.iter().enumerate() {
            if *b == b')' {
                if let Some(next) = bytes.get(index + 1) {
                    if matches!(next, b'*' | b'+' | b'?') {
                        found = true;
                    } else if *next == b'{' {
                        let rest = &source[index + 2..];
                        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if !digits.is_empty() {
                            found = true;
                        }
                    }
                }
            }
        }
        found
    };
    let backref = {
        let bytes = source.as_bytes();
        bytes.windows(2).any(|w| w[0] == b'\\' && (matches!(w[1], b'1'..=b'9')))
            || source.contains("\\k<")
    };
    if len < 1 || len > MAX_SETTING_PATTERN_LENGTH || source.contains("(?") || backref || quantified_group {
        return Some("pattern uses an unsafe regular-expression feature");
    }
    if regress::Regex::with_flags(source, "u").is_err() {
        return Some("pattern is invalid");
    }
    None
}

/// Test `value` against an ECMAScript `u` pattern.
pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    regress::Regex::with_flags(pattern, "u")
        .map(|re| re.find(value).is_some())
        .unwrap_or(false)
}

fn is_plain_record(value: &Value) -> bool {
    value.is_object()
}

/// `restrictedSettingSchemaErrors`.
pub fn restricted_setting_schema_errors(root: &Value, root_type: Option<&str>) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let mut stack = vec![(root, 0usize)];
    let mut nodes = 0;
    let forbidden = ["__proto__", "constructor", "prototype"];
    while let Some((schema_value, depth)) = stack.pop() {
        let Some(schema) = schema_value.as_object() else {
            errors.push("valueSchema must contain plain schema objects".into());
            continue;
        };
        nodes += 1;
        if nodes > MAX_RESTRICTED_SCHEMA_NODES || depth > MAX_RESTRICTED_SCHEMA_DEPTH {
            errors.push("valueSchema is too complex".into());
            break;
        }
        for keyword in schema.keys() {
            if !RESTRICTED_SCHEMA_KEYWORDS.contains(&keyword.as_str()) {
                errors.push(format!("valueSchema keyword is not allowed: {keyword}"));
            }
        }
        let ty = schema.get("type").and_then(Value::as_str).unwrap_or("");
        if !RESTRICTED_SCHEMA_TYPES.contains(&ty) {
            errors.push("every valueSchema node must declare one supported type".into());
        }
        if depth == 0 {
            if let Some(root_type) = root_type {
                if ty != root_type {
                    errors.push(format!("valueSchema root must use type {root_type}"));
                }
            }
        }
        if ty == "array" {
            match schema.get("items") {
                Some(items) if is_plain_record(items) => stack.push((items, depth + 1)),
                _ => errors.push("array valueSchema nodes require one items schema".into()),
            }
        } else if schema.contains_key("items") || schema.contains_key("minItems") || schema.contains_key("maxItems") {
            errors.push("valueSchema array keywords require type array".into());
        }
        if ty == "object" {
            match schema.get("properties").and_then(Value::as_object) {
                None => errors.push("object valueSchema nodes require properties".into()),
                Some(properties) => {
                    for (name, child) in properties {
                        let n = name.encode_utf16().count();
                        if n < 1 || n > 128 || name.contains('\0') || forbidden.contains(&name.as_str()) {
                            errors.push(format!("valueSchema property name is invalid: {name}"));
                        }
                        stack.push((child, depth + 1));
                    }
                    if let Some(required) = schema.get("required") {
                        let ok = required.as_array().is_some_and(|items| {
                            let set: HashSet<&Value> = items.iter().collect();
                            set.len() == items.len()
                                && items.iter().all(|n| n.as_str().is_some_and(|n| properties.contains_key(n)))
                        });
                        if !ok {
                            errors.push("valueSchema required fields are invalid".into());
                        }
                    }
                }
            }
            if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
                errors.push("object valueSchema nodes must deny additionalProperties".into());
            }
        } else if schema.contains_key("properties") || schema.contains_key("required") || schema.contains_key("additionalProperties") {
            errors.push("valueSchema object keywords require type object".into());
        }
        for name in ["minItems", "maxItems", "minLength", "maxLength"] {
            if let Some(v) = schema.get(name) {
                if !v.as_u64().is_some_and(|n| n <= (1u64 << 53) - 1) {
                    errors.push(format!("valueSchema {name} must be a non-negative safe integer"));
                }
            }
        }
        for name in ["minimum", "maximum"] {
            if let Some(v) = schema.get(name) {
                if !v.as_f64().is_some_and(f64::is_finite) {
                    errors.push(format!("valueSchema {name} must be finite"));
                }
            }
        }
        let num = |k: &str| schema.get(k).and_then(Value::as_f64);
        if let (Some(a), Some(b)) = (num("minItems"), num("maxItems")) {
            if a > b {
                errors.push("valueSchema minItems must not exceed maxItems".into());
            }
        }
        if let (Some(a), Some(b)) = (num("minLength"), num("maxLength")) {
            if a > b {
                errors.push("valueSchema minLength must not exceed maxLength".into());
            }
        }
        if let (Some(a), Some(b)) = (num("minimum"), num("maximum")) {
            if a > b {
                errors.push("valueSchema minimum must not exceed maximum".into());
            }
            if ty == "integer" && a.ceil() > b.floor() {
                errors.push("valueSchema integer range must contain a valid integer".into());
            }
        }
        if ty != "string" && (schema.contains_key("minLength") || schema.contains_key("maxLength")) {
            errors.push("valueSchema string keywords require type string".into());
        }
        if ty != "integer" && ty != "number" && (schema.contains_key("minimum") || schema.contains_key("maximum")) {
            errors.push("valueSchema numeric keywords require type number or integer".into());
        }
        if let Some(e) = schema.get("enum") {
            if !e.as_array().is_some_and(|items| !items.is_empty() && items.len() <= 256) {
                errors.push("valueSchema enum is invalid".into());
            }
        }
    }
    let mut seen = HashSet::new();
    errors.retain(|e| seen.insert(e.clone()));
    errors
}

/// Validate a value against a restricted (setting / configuration) schema.
pub fn restricted_schema_accepts(schema: &Value, value: &Value) -> PluginResult<bool> {
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(schema)
        .map_err(|e| PluginError::host(format!("valueSchema is invalid: {e}")))?;
    Ok(validator.is_valid(value))
}

fn provider_permissions(kind: &str) -> &'static [&'static str] {
    match kind {
        "terminal.completion" => &["provider.terminal", "terminal.complete"],
        "terminal.decoration" | "terminal.link" | "terminal.hover" | "terminal.matcher" | "terminal.prompt" => {
            &["provider.terminal", "terminal.output", "terminal.decorate"]
        }
        "terminal.semantic" => &["provider.terminal", "terminal.input", "terminal.decorate"],
        "terminal.background" | "terminal.theme" => &["provider.terminal", "terminal.decorate"],
        "terminal.interceptor.input" => &["provider.terminal", "terminal.intercept.input"],
        "terminal.interceptor.output" => &["provider.terminal", "terminal.intercept.output"],
        "connection" => &["provider.connection"],
        "authentication" => &["provider.authentication"],
        "sync" => &["provider.sync"],
        "importer" => &["provider.importer"],
        _ => &["provider.terminal"],
    }
}

fn validate_semantics(manifest: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let id = s(manifest, "id").unwrap_or("");
    // Duplicate / owned contribution ids.
    let groups: [(&str, &str, &[Value]); 6] = [
        ("settings", "setting", contributes(manifest, "settings")),
        ("commands", "command", contributes(manifest, "commands")),
        ("views", "view", contributes(manifest, "views")),
        ("themes", "theme", contributes(manifest, "themes")),
        ("providers", "provider", contributes(manifest, "providers")),
        ("companionExecutables", "companion executable", arr(manifest.get("companionExecutables"))),
    ];
    let mut ids: HashMap<String, &str> = HashMap::new();
    for (group, _, items) in &groups {
        for item in items.iter() {
            let Some(cid) = s(item, "id") else { continue };
            if let Some(previous) = ids.get(cid) {
                errors.push(format!("Duplicate contribution id across {previous} and {group}: {cid}"));
            } else {
                ids.insert(cid.to_string(), group);
            }
        }
    }
    let prefix = format!("{id}.");
    for (_, kind, items) in &groups {
        for item in items.iter() {
            if let Some(cid) = s(item, "id") {
                if !cid.starts_with(&prefix) {
                    errors.push(format!("{kind} id must start with the owning plugin id '{prefix}': {cid}"));
                }
            }
        }
    }
    let required_decls = declarations(manifest, "required");
    let optional_decls = declarations(manifest, "optional");
    for declaration in required_decls.iter().chain(optional_decls.iter()) {
        let Some(permission) = declaration.get("permission").and_then(Value::as_str) else { continue };
        let max = permission_resource_limit(permission);
        for resource in arr(declaration.get("resources")) {
            if resource.as_str().is_some_and(|r| r.encode_utf16().count() > max) {
                errors.push(format!("Permission resource for {permission} exceeds {max} characters"));
            }
        }
    }
    if let Some(engines) = manifest.get("engines").and_then(Value::as_object) {
        for (engine, range) in engines {
            let range = range.as_str().unwrap_or("");
            if !valid_range(range) {
                errors.push(format!("Invalid {engine} engine semver range: {range}"));
            }
        }
    }
    let version = s(manifest, "version").unwrap_or("");
    if !valid_version(version) {
        errors.push(format!("Invalid plugin semantic version: {version}"));
    }
    let features = manifest.get("features");
    let required_features: HashSet<&str> = arr(features.and_then(|f| f.get("required")))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let optional_features: Vec<&str> = arr(features.and_then(|f| f.get("optional")))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let declared_names: HashSet<&str> = required_decls
        .iter()
        .chain(optional_decls.iter())
        .filter_map(permission_name)
        .collect();
    if declared_names.contains("network.stream") && !required_features.contains("network.byte-streams") {
        errors.push("Byte streams require network.byte-streams".into());
    }
    if declared_names.contains("ai.invoke") && !required_features.contains("ai.model-invocation") {
        errors.push("AI invocation requires ai.model-invocation".into());
    }
    if (declared_names.contains("context.selected.list") || declared_names.contains("context.selected.read"))
        && !required_features.contains("context.selected-read")
    {
        errors.push("Selected context requires context.selected-read".into());
    }
    let all_features: HashSet<&str> = required_features.iter().copied().chain(optional_features.iter().copied()).collect();
    for (permission, feature) in [
        ("terminal.selection.read", "terminal.selection-sharing"),
        ("terminal.input.propose", "terminal.input-drafts"),
    ] {
        if optional_decls.iter().any(|p| permission_name(p) == Some(permission)) && !all_features.contains(feature) {
            errors.push(format!("{permission} requires {feature}"));
        }
    }
    let main = manifest.get("main").cloned().unwrap_or(Value::Null);
    let themes = contributes(manifest, "themes");
    if (main.get("data").is_some() || !themes.is_empty()) && !required_features.contains("appearance.theme-packs") {
        errors.push("Theme packs require appearance.theme-packs".into());
    }
    for theme in themes {
        if !s(theme, "entry").unwrap_or("").ends_with(".json") {
            errors.push("Theme palette entry must be JSON".into());
        }
    }
    let views = contributes(manifest, "views");
    if views.iter().any(|v| s(v, "location") == Some("terminal-sidebar")) && !required_features.contains("views.terminal-sidebar") {
        errors.push("Terminal sidebar pages require views.terminal-sidebar".into());
    }
    if views.iter().any(|v| s(v, "location") == Some("vault-page")) && !required_features.contains("views.vault-pages") {
        errors.push("Vault pages require views.vault-pages".into());
    }
    let commands = contributes(manifest, "commands");
    if commands.iter().any(|c| c.get("interactive").and_then(Value::as_bool) == Some(true))
        && !required_features.contains("commands.interactive")
    {
        errors.push("Interactive commands require commands.interactive".into());
    }
    if let Some(icon) = manifest.get("icon") {
        if !required_features.contains("metadata.brand-icon") {
            errors.push("Brand icons require metadata.brand-icon".into());
        }
        let api = manifest.get("engines").and_then(|e| s(e, "api")).unwrap_or("");
        if !valid_range(api) || !satisfies("0.1.0-internal.1", api) || satisfies("0.1.0-internal", api) {
            errors.push("Brand icons require API >=0.1.0-internal.1 excluding the legacy revision".into());
        }
        for path in package_icon_paths(Some(icon)) {
            if !(path.ends_with(".png") || path.ends_with(".webp")) {
                errors.push("Brand icons require PNG or WebP paths".into());
            }
        }
    }
    for feature in &optional_features {
        if required_features.contains(feature) {
            errors.push(format!("Feature cannot be both required and optional: {feature}"));
        }
    }
    let mut companion_paths = HashSet::new();
    for companion in arr(manifest.get("companionExecutables")) {
        let mut platforms = HashSet::new();
        for variant in arr(companion.get("variants")) {
            let path = s(variant, "path").unwrap_or("");
            if !companion_paths.insert(path.to_string()) {
                errors.push(format!("Duplicate companion executable path: {path}"));
            }
            for platform in arr(variant.get("platforms")).iter().filter_map(Value::as_str) {
                if !platforms.insert(platform) {
                    errors.push(format!(
                        "Duplicate companion platform for {}: {platform}",
                        s(companion, "id").unwrap_or("")
                    ));
                }
            }
        }
    }
    let required_names: HashSet<&str> = required_decls.iter().filter_map(permission_name).collect();
    if required_names.len() != required_decls.len() {
        errors.push("Required permissions must not contain duplicate permission names".into());
    }
    let optional_names: HashSet<&str> = optional_decls.iter().filter_map(permission_name).collect();
    if optional_names.len() != optional_decls.len() {
        errors.push("Optional permissions must not contain duplicate permission names".into());
    }
    for name in optional_decls.iter().filter_map(permission_name) {
        if required_names.contains(name) {
            errors.push(format!("Permission cannot be both required and optional: {name}"));
        }
    }
    let declared: HashSet<&str> = required_names.union(&optional_names).copied().collect();
    let require = |condition: bool, permission: &str, reason: &str, errors: &mut Vec<String>| {
        if condition && !declared.contains(permission) {
            errors.push(format!("{reason} requires declared permission: {permission}"));
        }
    };
    require(!contributes(manifest, "settings").is_empty(), "settings.read", "Setting contributions", &mut errors);
    require(main.get("node").is_some(), "runtime.advanced", "Node utility entrypoints", &mut errors);
    require(!commands.is_empty(), "commands", "Command contributions", &mut errors);
    require(!contributes(manifest, "menus").is_empty(), "menus", "Menu contributions", &mut errors);
    require(!views.is_empty(), "views", "View contributions", &mut errors);
    let companions = arr(manifest.get("companionExecutables"));
    require(!companions.is_empty(), "companion.execute", "Companion executables", &mut errors);
    require(!companions.is_empty(), "runtime.advanced", "Companion executables", &mut errors);
    if !companions.is_empty() && main.get("node").is_none() {
        errors.push("Companion executables require a Node utility entrypoint".into());
    }
    for provider in contributes(manifest, "providers") {
        let pid = s(provider, "id").unwrap_or("");
        let kind = s(provider, "kind").unwrap_or("");
        for permission in provider_permissions(kind) {
            require(true, permission, &format!("Provider {pid}"), &mut errors);
        }
        if kind == "terminal.interceptor.input" || kind == "terminal.interceptor.output" {
            require(true, "runtime.advanced", &format!("Provider {pid}"), &mut errors);
            if main.get("node").is_none() {
                errors.push(format!("Provider {pid} requires a Node utility entrypoint"));
            }
        }
        if let Some(schema) = provider.get("configurationSchema") {
            for error in restricted_setting_schema_errors(schema, None) {
                errors.push(format!("Provider {pid} configurationSchema {error}"));
            }
        }
    }
    for companion in companions {
        for permission in arr(companion.get("permissions")).iter().filter_map(Value::as_str) {
            require(true, permission, &format!("Companion executable {}", s(companion, "id").unwrap_or("")), &mut errors);
        }
    }
    let command_ids: HashSet<&str> = commands.iter().filter_map(|c| s(c, "id")).collect();
    let view_ids: HashSet<&str> = views.iter().filter_map(|c| s(c, "id")).collect();
    let provider_ids: HashSet<&str> = contributes(manifest, "providers").iter().filter_map(|c| s(c, "id")).collect();
    for menu in contributes(manifest, "menus") {
        let command = s(menu, "command").unwrap_or("");
        if !command_ids.contains(command) {
            errors.push(format!("Menu references an undeclared command: {command}"));
        }
        if let Some(alt) = s(menu, "alt") {
            if !command_ids.contains(alt) {
                errors.push(format!("Menu references an undeclared alternate command: {alt}"));
            }
        }
    }
    for keybinding in contributes(manifest, "keybindings") {
        let command = s(keybinding, "command").unwrap_or("");
        if !command_ids.contains(command) {
            errors.push(format!("Keybinding references an undeclared command: {command}"));
        }
    }
    for event in arr(manifest.get("activationEvents")).iter().filter_map(Value::as_str) {
        for (prefix, kind, ids) in [
            ("onCommand:", "command", &command_ids),
            ("onView:", "view", &view_ids),
            ("onProvider:", "provider", &provider_ids),
        ] {
            if let Some(target) = event.strip_prefix(prefix) {
                if !ids.contains(target) {
                    errors.push(format!("Activation event references an undeclared {kind}: {target}"));
                }
            }
        }
    }
    for setting in contributes(manifest, "settings") {
        validate_setting(setting, &mut errors);
    }
    let mut entry_paths = referenced_paths(manifest);
    entry_paths.extend(companion_variants(manifest).into_iter().map(|(p, _)| p));
    for path in entry_paths {
        if let Err(err) = assert_safe_package_path(&path) {
            errors.push(err.message().to_string());
        }
    }
    errors
}

fn validate_setting(setting: &Value, errors: &mut Vec<String>) {
    let id = s(setting, "id").unwrap_or("");
    let control = s(setting, "control").unwrap_or("");
    let secret = setting.get("secret").and_then(Value::as_bool) == Some(true);
    let sync = setting.get("sync").and_then(Value::as_bool) == Some(true);
    let default = setting.get("default");
    let is_choice = matches!(control, "radio" | "select" | "multiselect");
    let is_numeric = matches!(control, "number" | "slider");
    let is_list = matches!(control, "list" | "table");
    if secret && default.is_some() {
        errors.push(format!("Secret setting must not declare a default value: {id}"));
    }
    let options = setting.get("options");
    if is_choice && arr(options).is_empty() {
        errors.push(format!("{control} setting requires options: {id}"));
    }
    let mut option_values = HashSet::new();
    for option in arr(options) {
        let value = s(option, "value").unwrap_or("").to_string();
        if !option_values.insert(value.clone()) {
            errors.push(format!("{control} setting has duplicate option value '{value}': {id}"));
        }
    }
    if !is_choice && options.is_some() {
        errors.push(format!("{control} setting must not declare options: {id}"));
    }
    let num = |k: &str| setting.get(k).and_then(Value::as_f64);
    if is_numeric {
        if let (Some(min), Some(max)) = (num("minimum"), num("maximum")) {
            if min > max {
                errors.push(format!("{control} setting minimum exceeds maximum: {id}"));
            }
        }
    }
    if control == "slider" && (setting.get("minimum").is_none() || setting.get("maximum").is_none()) {
        errors.push(format!("slider setting requires minimum and maximum: {id}"));
    }
    if !is_numeric && (setting.get("minimum").is_some() || setting.get("maximum").is_some() || setting.get("step").is_some()) {
        errors.push(format!("{control} setting must not declare numeric bounds: {id}"));
    }
    let pattern = s(setting, "pattern");
    if pattern.is_some() && !matches!(control, "text" | "textarea" | "password") {
        errors.push(format!("{control} setting must not declare a text pattern: {id}"));
    }
    if let Some(pattern) = pattern {
        if let Some(error) = setting_pattern_error(pattern) {
            errors.push(format!("{control} setting {error}: {id}"));
        } else if let Some(text) = default.and_then(Value::as_str) {
            if !pattern_matches(pattern, text) {
                errors.push(format!("{control} setting default does not match its pattern: {id}"));
            }
        }
    }
    if control == "password" && !secret {
        errors.push(format!("password setting must be marked secret: {id}"));
    }
    if secret && control != "password" {
        errors.push(format!("Secret setting must use the password control: {id}"));
    }
    if secret && sync {
        errors.push(format!("Secret setting must not be cloud-synced: {id}"));
    }
    let scope = s(setting, "scope").unwrap_or("");
    if sync && matches!(scope, "device" | "session") {
        errors.push(format!("{scope}-scoped setting must not be cloud-synced: {id}"));
    }
    if sync && matches!(control, "file" | "directory") {
        errors.push(format!("{control} setting paths must not be cloud-synced: {id}"));
    }
    let value_schema = setting.get("valueSchema");
    if is_list && value_schema.is_none() {
        errors.push(format!("{control} setting requires valueSchema: {id}"));
    }
    if is_list {
        if let Some(schema) = value_schema {
            let schema_errors = restricted_setting_schema_errors(schema, Some("array"));
            for error in &schema_errors {
                errors.push(format!("{control} setting {error}: {id}"));
            }
            if schema_errors.is_empty() {
                match restricted_schema_accepts(schema, default.unwrap_or(&Value::Array(vec![]))) {
                    Ok(accepted) => {
                        if default.is_some() && !accepted {
                            errors.push(format!("{control} setting default does not match valueSchema: {id}"));
                        }
                    }
                    Err(err) => errors.push(format!("{control} setting valueSchema is invalid: {id}: {}", err.message())),
                }
            }
        }
    }
    if !is_list && value_schema.is_some() {
        errors.push(format!("{control} setting must not declare valueSchema: {id}"));
    }
    if !is_list && setting.get("sortable").and_then(Value::as_bool) == Some(true) {
        errors.push(format!("{control} setting must not be sortable: {id}"));
    }
    let Some(default) = default else { return };
    let string_controls = ["radio", "select", "text", "textarea", "password", "color", "font", "file", "directory", "keybinding"];
    if control == "switch" && !default.is_boolean() {
        errors.push(format!("switch setting default must be boolean: {id}"));
    }
    if string_controls.contains(&control) && !default.is_string() {
        errors.push(format!("{control} setting default must be a string: {id}"));
    }
    if is_numeric && !default.as_f64().is_some_and(f64::is_finite) {
        errors.push(format!("{control} setting default must be a finite number: {id}"));
    }
    if is_list && !default.is_array() {
        errors.push(format!("{control} setting default must be an array: {id}"));
    }
    if control == "multiselect" {
        match default.as_array() {
            Some(items) if items.iter().all(Value::is_string) => {
                let mut selected = HashSet::new();
                for value in items.iter().filter_map(Value::as_str) {
                    if !option_values.contains(value) {
                        errors.push(format!("multiselect setting default uses an undeclared option '{value}': {id}"));
                    }
                    if !selected.insert(value) {
                        errors.push(format!("multiselect setting default repeats option '{value}': {id}"));
                    }
                }
            }
            _ => errors.push(format!("multiselect setting default must be a string array: {id}")),
        }
    }
    if matches!(control, "radio" | "select") {
        if let Some(value) = default.as_str() {
            if !option_values.contains(value) {
                errors.push(format!("{control} setting default uses an undeclared option '{value}': {id}"));
            }
        }
    }
    if let Some(value) = default.as_f64().filter(|v| v.is_finite()) {
        if let Some(min) = num("minimum") {
            if value < min {
                errors.push(format!("{control} setting default is below minimum: {id}"));
            }
        }
        if let Some(max) = num("maximum") {
            if value > max {
                errors.push(format!("{control} setting default is above maximum: {id}"));
            }
        }
        if let Some(step) = num("step") {
            let steps = (value - num("minimum").unwrap_or(0.0)) / step;
            if (steps - steps.round()).abs() > 1e-9 {
                errors.push(format!("{control} setting default does not align to step: {id}"));
            }
        }
    }
}

/// `validateManifestValue`.
pub fn validate_manifest_value(value: &Value) -> ManifestValidation {
    if let Err(err) = assert_manifest_json_structure(value) {
        return ManifestValidation { manifest: None, errors: vec![err] };
    }
    let bounds = validate_required_permission_bounds(value);
    if !bounds.is_empty() {
        return ManifestValidation { manifest: None, errors: bounds };
    }
    match contract::definition_validator("PluginManifest") {
        Ok(validator) => {
            let errors: Vec<String> = validator
                .iter_errors(value)
                .map(|err| {
                    let path = err.instance_path.to_string();
                    format!("{} {}", if path.is_empty() { "/" } else { &path }, err)
                })
                .collect();
            if !errors.is_empty() {
                return ManifestValidation { manifest: None, errors };
            }
        }
        Err(err) => return ManifestValidation { manifest: None, errors: vec![err.message().to_string()] },
    }
    let errors = validate_semantics(value);
    if errors.is_empty() {
        ManifestValidation { manifest: Some(value.clone()), errors }
    } else {
        ManifestValidation { manifest: None, errors }
    }
}

/// `parseAndValidateManifestContents`.
pub fn parse_and_validate_manifest(contents: &[u8]) -> PluginResult<Value> {
    if contents.len() > super::limits::MANIFEST_BYTES {
        return Err(PluginError::host(format!(
            "Plugin manifest exceeds {} bytes",
            super::limits::MANIFEST_BYTES
        )));
    }
    let text = std::str::from_utf8(contents)
        .map_err(|e| PluginError::host(format!("Plugin manifest is not valid UTF-8 JSON: {e}")))?;
    let value: Value = serde_json::from_str(text)
        .map_err(|e| PluginError::host(format!("Plugin manifest is not valid UTF-8 JSON: {e}")))?;
    let result = validate_manifest_value(&value);
    match result.manifest {
        Some(manifest) => Ok(manifest),
        None => Err(PluginError::host(format!(
            "Plugin manifest is invalid:\n- {}",
            result.errors.join("\n- ")
        ))),
    }
}

/// Convenience used by tests and other modules.
pub fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}
