// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // EternalTerminal sessions point `SSH_ASKPASS` at this executable; answer
    // the prompt and exit before any window is created.
    if let Some(code) = netcatty_desktop_lib::askpass::run_if_requested() {
        std::process::exit(code);
    }
    if let Some(code) = netcatty_desktop_lib::mcp_helper::run_if_requested() {
        std::process::exit(code);
    }
    // FIDO2: OpenSSH (ssh-add / ssh-keygen / ssh-sk-helper) asks for PINs
    // and touch through this executable (`NETCATTY_FIDO_ASKPASS=1`).
    if let Some(code) = netcatty_fido::run_helper_if_requested() {
        std::process::exit(code);
    }
    netcatty_desktop_lib::run()
}
