//! The capability catalog (Electron `electron/capabilities/catalog/*.cjs` and
//! `schemas/toolInputs.cjs`), exported verbatim to `data/catalog.json` so
//! tool names, descriptions and schemas match what external agents were
//! prompted with. Regenerate with:
//!
//! ```sh
//! node -e 'const fs=require("fs");const {ALL_CAPABILITIES}=require("./electron/capabilities/catalog/index.cjs");const {TOOL_INPUT_FIELDS,MODEL_DESCRIPTION_HINTS}=require("./electron/capabilities/schemas/toolInputs.cjs");fs.writeFileSync("rust/crates/netcatty-capabilities/data/catalog.json",JSON.stringify({capabilities:ALL_CAPABILITIES,toolInputFields:TOOL_INPUT_FIELDS,modelDescriptionHints:MODEL_DESCRIPTION_HINTS},null,1)+"\n")'
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

pub const SURFACE_BUILTIN: &str = "builtin";
pub const SURFACE_PUBLIC: &str = "public";
pub const SURFACE_CLI: &str = "cli";
pub const SURFACE_GLOBAL: &str = "global";
pub const SURFACE_CATTY: &str = "catty";
pub const SURFACE_GLOBAL_AGENT: &str = "globalAgent";

pub const STATUS_IMPLEMENTED: &str = "implemented";
pub const STATUS_PLANNED: &str = "planned";

pub const MODE_OBSERVER: &str = "observer";
pub const MODE_CONFIRM: &str = "confirm";
pub const MODE_AUTO: &str = "auto";

pub const DEFAULT_RPC_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_OPERATION_TIMEOUT_MS: u64 = 60_000;
pub const RPC_TIMEOUT_BUFFER_MS: u64 = 5_000;
pub const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 110_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPolicy {
    pub write: bool,
    pub sensitive_read: bool,
    pub long_running: bool,
    pub requires_chat_session: bool,
    pub bypasses_observer_block: bool,
    pub bypasses_approval: bool,
    pub bypasses_chat_cancel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_in_confirm_mode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub description: String,
    pub policy: CapabilityPolicy,
    pub surfaces: BTreeMap<String, SurfaceBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_kinds: Option<Vec<String>>,
}

impl Capability {
    pub fn surface(&self, surface: &str) -> Option<&SurfaceBinding> {
        self.surfaces.get(surface)
    }

    pub fn is_implemented(&self) -> bool {
        self.status == STATUS_IMPLEMENTED
    }
}

/// One input field of a tool schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InputField {
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub allow_empty: bool,
    #[serde(default)]
    pub description: String,
}

/// Field order matters (schemas and CLI params are emitted in catalog order).
pub type InputFields = Vec<(String, InputField)>;

/// JSON object deserialized as an ordered list of pairs.
struct Ordered<V>(Vec<(String, V)>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Ordered<V> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<V> {
            type Value = Ordered<V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, V>()? {
                    out.push((k, v));
                }
                Ok(Ordered(out))
            }
        }
        d.deserialize_map(Visitor(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCatalog {
    capabilities: Vec<Capability>,
    tool_input_fields: Ordered<Ordered<InputField>>,
    model_description_hints: BTreeMap<String, String>,
}

pub struct Catalog {
    pub capabilities: Vec<Capability>,
    pub tool_input_fields: BTreeMap<String, InputFields>,
    pub model_description_hints: BTreeMap<String, String>,
}

pub static CATALOG: LazyLock<Catalog> = LazyLock::new(|| {
    let raw: RawCatalog = serde_json::from_str(include_str!("../data/catalog.json")).expect("catalog.json is valid");
    let tool_input_fields = raw
        .tool_input_fields
        .0
        .into_iter()
        .map(|(id, fields)| (id, fields.0))
        .collect();
    Catalog {
        capabilities: raw.capabilities,
        tool_input_fields,
        model_description_hints: raw.model_description_hints,
    }
});

pub fn all_capabilities() -> &'static [Capability] {
    &CATALOG.capabilities
}

pub fn tool_input_fields(capability_id: &str) -> Option<&'static InputFields> {
    CATALOG.tool_input_fields.get(capability_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_loads_with_unique_ids_and_bindings() {
        let caps = all_capabilities();
        assert_eq!(caps.len(), 80);
        let ids: HashSet<_> = caps.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids.len(), caps.len());
        for cap in caps.iter().filter(|c| c.is_implemented()) {
            assert!(!cap.surfaces.is_empty(), "{} has no surface", cap.id);
        }
        // Field order is preserved (JSON key order).
        let fields = tool_input_fields("terminal.execute").unwrap();
        assert_eq!(fields[0].0, "sessionId");
        assert_eq!(fields[1].0, "command");
    }

    #[test]
    fn every_cli_command_maps_to_an_rpc_method() {
        for cap in all_capabilities().iter().filter(|c| c.is_implemented()) {
            if cap.surface(SURFACE_CLI).and_then(|b| b.command.as_ref()).is_some() {
                let has = [SURFACE_BUILTIN, SURFACE_GLOBAL, SURFACE_PUBLIC]
                    .iter()
                    .any(|s| cap.surface(s).and_then(|b| b.rpc_method.as_ref()).is_some());
                assert!(has, "{} cli without rpc", cap.id);
            }
        }
    }
}
