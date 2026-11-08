//! End-to-end compatibility: build the first-party example plugins
//! (`examples/plugins/hello-netcatty`, `starter-netcatty`) into `.ncpkg`
//! archives, install them into a Rust host and drive them over the real
//! plugin JSON-RPC contract through `runtimePeer.mjs` (the same runtime the
//! Electron host and the Tauri webview iframe run), using the Node sidecar
//! transport.
//!
//! Skips (with a message) when `node` is not available or the examples are
//! not built (`npm run build:plugin-packages`).

use netcatty_plugins::host::{HostConfig, HostEvents, PluginHost};
use netcatty_plugins::manager::InstallRequest;
use netcatty_plugins::package::archive::build_package;
use netcatty_plugins::runtime::{default_node_runtime_config, find_node, NodeSidecarLauncher};
use netcatty_plugins::secrets::SecretCipher;
use netcatty_plugins::source::Source;
use netcatty_plugins::PluginResult;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct ReverseCipher;
impl SecretCipher for ReverseCipher {
    fn available(&self) -> bool {
        true
    }
    fn encrypt(&self, plaintext: &str) -> PluginResult<Vec<u8>> {
        Ok(plaintext.bytes().rev().collect())
    }
    fn decrypt(&self, ciphertext: &[u8]) -> PluginResult<String> {
        Ok(String::from_utf8(ciphertext.iter().rev().copied().collect()).unwrap())
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<(String, Value)>>);
impl HostEvents for Recorder {
    fn emit(&self, channel: &str, payload: Value) {
        self.0.lock().push((channel.to_string(), payload));
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn prerequisites() -> Option<PathBuf> {
    let root = repo_root();
    if find_node(None).is_none() {
        eprintln!("skipping: node is not available");
        return None;
    }
    for example in ["hello-netcatty/dist/index.js", "starter-netcatty/dist/host.js"] {
        if !root.join("examples/plugins").join(example).exists() {
            eprintln!("skipping: run `npm run build:plugin-packages` first ({example} missing)");
            return None;
        }
    }
    if !root.join("node_modules/@netcatty/plugin-sdk/dist/index.js").exists() {
        eprintln!("skipping: @netcatty/plugin-sdk is not built");
        return None;
    }
    Some(root)
}

fn host(dir: &Path, root: &Path, events: Arc<Recorder>) -> Arc<PluginHost> {
    let node = default_node_runtime_config(root);
    let host = PluginHost::new(HostConfig {
        user_data: dir.to_path_buf(),
        netcatty_version: "1.2.1".into(),
        allow_advanced_plugins: false,
        node: Some(node.clone()),
        cipher: Arc::new(ReverseCipher),
        events,
    })
    .unwrap();
    // Browser-entry plugins run in the webview iframe in the app; here the
    // same runtimePeer runs under Node, speaking the identical RPC contract.
    host.supervisor.set_browser_launcher(Arc::new(NodeSidecarLauncher { config: node }));
    host
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_and_starter_examples_run_against_the_rust_host() {
    let Some(root) = prerequisites() else { return };
    let data = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let events = Arc::new(Recorder::default());
    let host = host(data.path(), &root, events.clone());
    host.manager.initialize().await.unwrap();

    // --- hello -----------------------------------------------------------
    let hello = out.path().join("hello.ncpkg");
    build_package(&root.join("examples/plugins/hello-netcatty"), &hello).unwrap();
    let installed = host
        .manager
        .install(InstallRequest { archive_path: hello, enable: Some(true), source: Source::local(), catalog: None })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(installed.id, "com.netcatty.hello");
    assert!(installed.enabled);

    // Lazy activation on command; the plugin reads its setting over RPC.
    let result = host
        .contributions
        .execute_command("com.netcatty.hello.sayHello", None, "renderer", None, None)
        .await
        .unwrap();
    assert_eq!(result, json!({ "greeting": "Hello from Netcatty" }));
    let plugin = host.database.get_active_plugin("com.netcatty.hello").unwrap().unwrap();
    assert_eq!(plugin.runtime.status, "running");

    host.contributions
        .update_setting("com.netcatty.hello", "com.netcatty.hello.greeting", &json!("Hi from Rust"), None, "host")
        .await
        .unwrap();
    let result = host
        .contributions
        .execute_command("com.netcatty.hello.sayHello", None, "renderer", None, None)
        .await
        .unwrap();
    assert_eq!(result, json!({ "greeting": "Hi from Rust" }));

    // Contribution snapshot (localized, settings with stored values).
    let snapshot = host.contributions.snapshot(&json!({ "locale": "zh-CN" })).unwrap();
    let entry = &snapshot["plugins"][0];
    assert_eq!(entry["displayName"], json!("你好，Netcatty"));
    assert_eq!(entry["settings"][0]["value"], json!("Hi from Rust"));
    assert_eq!(entry["menus"][0]["visible"], json!(true));

    // Restart keeps it working; disable stops it.
    host.manager.restart("com.netcatty.hello").await.unwrap();
    assert_eq!(host.database.get_active_plugin("com.netcatty.hello").unwrap().unwrap().runtime.status, "running");
    host.manager.set_enabled("com.netcatty.hello", false, None).await.unwrap();
    assert_eq!(host.database.get_active_plugin("com.netcatty.hello").unwrap().unwrap().runtime.status, "stopped");
    assert!(host
        .contributions
        .execute_command("com.netcatty.hello.sayHello", None, "renderer", None, None)
        .await
        .is_err());

    // --- starter ---------------------------------------------------------
    let starter = out.path().join("starter.ncpkg");
    build_package(&root.join("examples/plugins/starter-netcatty"), &starter).unwrap();
    host.manager
        .install(InstallRequest { archive_path: starter, enable: Some(true), source: Source::local(), catalog: None })
        .await
        .unwrap();
    let posted: Arc<Mutex<Vec<Value>>> = Arc::default();
    let sink = posted.clone();
    host.contributions.on_did_post_view_message(Arc::new(move |event| sink.lock().push(event.clone())));
    let result = host
        .contributions
        .execute_command("com.netcatty.starter.greet", None, "renderer", None, None)
        .await
        .unwrap();
    assert_eq!(result, json!({ "greeting": "Hello, synthetic world!" }));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(posted.lock()[0]["viewId"], json!("com.netcatty.starter.panel"));

    assert!(host.manager.uninstall("com.netcatty.starter").await.unwrap());
    assert!(host.manager.uninstall("com.netcatty.hello").await.unwrap());
    assert!(events.0.lock().iter().any(|(c, _)| c == "netcatty:plugins:contributions-changed"));
    host.shutdown().await;
}
