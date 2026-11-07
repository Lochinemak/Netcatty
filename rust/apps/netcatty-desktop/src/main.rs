// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // EternalTerminal sessions point `SSH_ASKPASS` at this executable; answer
    // the prompt and exit before any window is created.
    if let Some(code) = netcatty_desktop_lib::askpass::run_if_requested() {
        std::process::exit(code);
    }
    netcatty_desktop_lib::run()
}
