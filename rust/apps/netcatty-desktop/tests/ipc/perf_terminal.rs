//! Terminal output throughput (ignored by default; run with
//! `cargo test --release -p netcatty-desktop --test ipc perf_terminal -- --ignored --nocapture`).
//!
//! Measures the backend half of the hot path: local PTY → pump → taps →
//! `netcatty:data` emit. `MockRuntime` does not evaluate the per-window JS,
//! so the webview half (one `eval` + `JSON.parse` per window per event) is
//! not in these numbers.

use super::ipc_smoke::{build_app, invoke, ok};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Listener;

#[derive(Default)]
struct Seen {
    sizes: Vec<usize>,
    done_at: Option<Instant>,
}

fn cpu_seconds() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    // [[dd-]hh:]mm:ss.ss
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    text.split(':').fold(0.0, |acc, part| acc * 60.0 + part.parse::<f64>().unwrap_or(0.0))
}

fn percentile(sorted: &[usize], p: f64) -> usize {
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

/// Run `script` in a local `/bin/sh` session and report what reached the
/// renderer side. The script must print `__NC_DONE__` last; it is written
/// split (`__NC_""DONE__`) so the echoed command line does not match.
fn run(label: &str, script: &str, extra_windows: usize) {
    let h = build_app();
    let _extra: Vec<_> = (0..extra_windows)
        .map(|i| tauri::WebviewWindowBuilder::new(&h.app, format!("extra-{i}"), Default::default()).build().unwrap())
        .collect();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let sink = seen.clone();
    h.app.listen_any("netcatty:data", move |e| {
        let payload = e.payload();
        let mut seen = sink.lock().unwrap();
        seen.sizes.push(payload.len());
        if seen.done_at.is_none() && payload.contains("__NC_DONE__") {
            seen.done_at = Some(Instant::now());
        }
    });
    let started = ok(invoke(&h.webview, "session_start_local", json!({ "payload": { "shell": "/bin/sh", "cols": 200, "rows": 50 } })));
    let id = started["sessionId"].as_str().unwrap().to_string();
    std::thread::sleep(Duration::from_millis(500));
    seen.lock().unwrap().sizes.clear();

    let cpu0 = cpu_seconds();
    let t0 = Instant::now();
    ok(invoke(&h.webview, "session_write", json!({ "payload": { "sessionId": id, "data": format!("{script}\n") } })));
    let deadline = t0 + Duration::from_secs(120);
    while seen.lock().unwrap().done_at.is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let seen = seen.lock().unwrap();
    let elapsed = seen.done_at.expect("marker not seen within 120 s").duration_since(t0).as_secs_f64();
    let cpu = cpu_seconds() - cpu0;
    let mut sizes = seen.sizes.clone();
    sizes.sort_unstable();
    let total: usize = sizes.iter().sum();
    let small = sizes.iter().filter(|&&s| s < 4096).count();
    println!(
        "{label:<34} windows={:<2} {:>7.1} MB in {:>6.2}s = {:>6.1} MB/s | events {:>6} (<4KB: {:>5}) | size p50 {:>6} p95 {:>6} max {:>6} | test-process CPU {:>5.2}s",
        1 + extra_windows,
        total as f64 / 1e6,
        elapsed,
        total as f64 / 1e6 / elapsed,
        sizes.len(),
        small,
        percentile(&sizes, 0.5),
        percentile(&sizes, 0.95),
        sizes.last().copied().unwrap_or(0),
        cpu,
    );
    let _ = invoke(&h.webview, "session_close", json!({ "payload": { "sessionId": id } }));
}

const BULK: &str = "yes 'netcatty throughput line 0123456789 abcdefghijklmnopqrstuvwxyz' | head -c 33554432; echo __NC_\"\"DONE__";
const DRIP: &str = "i=0; while [ $i -lt 20000 ]; do echo \"line $i of a slowly printed log\"; i=$((i+1)); done; echo __NC_\"\"DONE__";

#[cfg(unix)]
#[test]
#[ignore]
fn perf_terminal_bulk_and_drip() {
    for _ in 0..3 {
        run("bulk 32 MiB (yes | head)", BULK, 0);
        run("bulk 32 MiB (yes | head)", BULK, 2);
        run("drip 20k echo lines", DRIP, 0);
    }
}
