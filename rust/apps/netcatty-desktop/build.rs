fn main() {
    // Host browser proxy (wry `mac-proxy`) links Network.framework symbols that
    // exist only on macOS 14+. Weak-link the framework so older systems still
    // launch; `commands::hostbrowser::proxy_support` refuses SSH routes there.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-weak_framework,Network");
    }
    tauri_build::build()
}
