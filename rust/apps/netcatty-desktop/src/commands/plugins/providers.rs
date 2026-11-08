//! Catalog, themes, icons, views and provider methods of `plugin_call`.

use super::PluginsState;
use netcatty_plugins::host::PluginHost;
use netcatty_plugins::{PluginError, PluginResult};
use serde_json::Value;
use std::sync::Arc;
use tauri::{AppHandle, Runtime};

pub(super) async fn dispatch<R: Runtime>(
    _app: &AppHandle<R>,
    _state: &PluginsState,
    _host: &Arc<PluginHost>,
    _owner: &str,
    method: &str,
    _payload: Value,
) -> PluginResult<Value> {
    Err(PluginError::rpc(netcatty_plugins::codes::UNSUPPORTED, format!("Unsupported plugin bridge method: {method}")))
}
