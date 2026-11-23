//! Real-runtime check of the host browser's engine download hook
//! (`commands::hostbrowser::native`), which the headless IPC tests cannot
//! reach: `MockRuntime` has no web view.
//!
//! It serves a few files on a local HTTP server and runs two passes with real
//! navigations:
//!
//! * **engine** — one hidden page window with the hook alone: a slow binary
//!   (byte progress, then cancel), an inline PDF and an `attachment` (both
//!   must become downloads), and the same PDF again after the hook is removed
//!   (must be shown, as wry does on its own);
//! * **commands** — the host browser commands on a local route, as the
//!   renderer calls them: the download list shows growing byte counts,
//!   `cancel` stops the transfer and removes the partial file, a PDF ends up
//!   as a completed download, and closing the browser stops a running one.
//!
//! `HOME` and the data directory point at a temporary directory, so nothing
//! is written to the user's Downloads folder or profile.
//!
//! ```bash
//! cargo run -p netcatty-desktop --example hostbrowser_native_probe
//! ```
//!
//! Exits 0 when every check passes. macOS only: the hook is not implemented
//! for the other engines.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("hostbrowser_native_probe: the engine download hook exists on macOS only");
}

#[cfg(target_os = "macos")]
fn main() {
    probe::run();
}

#[cfg(target_os = "macos")]
mod probe {
    use netcatty_desktop_lib::commands::hostbrowser::native::{self, Progress};
    use netcatty_desktop_lib::commands::hostbrowser::{self as hostbrowser, HostBrowserState};
    use netcatty_desktop_lib::state::AppState;
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tauri::webview::DownloadEvent;
    use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    const LABEL: &str = "probe";
    const MAIN: &str = "main";
    const SLOW_BYTES: usize = 8 * 1024 * 1024;
    const PDF: &[u8] = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n";

    #[derive(Debug)]
    enum Event {
        Requested {
            id: String,
            url: String,
            path: PathBuf,
            claimed: bool,
        },
        Finished {
            url: String,
            success: bool,
        },
    }

    async fn serve(listener: tokio::net::TcpListener) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => request.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                let path = String::from_utf8_lossy(&request)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                let head = |kind: &str, len: usize, extra: &str| {
                    format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {len}\r\n{extra}Connection: close\r\n\r\n")
                };
                match path.split('?').next().unwrap_or("/") {
                    "/slow.bin" => {
                        if socket
                            .write_all(head("application/octet-stream", SLOW_BYTES, "").as_bytes())
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let chunk = vec![7u8; 64 * 1024];
                        for _ in 0..SLOW_BYTES / chunk.len() {
                            if socket.write_all(&chunk).await.is_err() {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                    "/doc.pdf" => {
                        let _ = socket
                            .write_all(head("application/pdf", PDF.len(), "").as_bytes())
                            .await;
                        let _ = socket.write_all(PDF).await;
                    }
                    "/note.txt" => {
                        let body = b"saved, not shown\n";
                        let extra = "Content-Disposition: attachment; filename=\"note.txt\"\r\n";
                        let _ = socket
                            .write_all(head("text/plain", body.len(), extra).as_bytes())
                            .await;
                        let _ = socket.write_all(body).await;
                    }
                    _ => {
                        let body = b"<!doctype html><title>probe</title><p>probe</p>";
                        let _ = socket
                            .write_all(head("text/html", body.len(), "").as_bytes())
                            .await;
                        let _ = socket.write_all(body).await;
                    }
                }
                let _ = socket.shutdown().await;
            });
        }
    }

    /// Run `f` on the main thread and hand its result back.
    async fn on_main<T: Send + 'static>(
        app: &AppHandle,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = tokio::sync::oneshot::channel();
        app.run_on_main_thread(move || {
            let _ = tx.send(f());
        })
        .expect("main thread is running");
        rx.await.expect("main thread answered")
    }

    async fn next(events: &mut mpsc::UnboundedReceiver<Event>, within: Duration) -> Option<Event> {
        tokio::time::timeout(within, events.recv())
            .await
            .ok()
            .flatten()
    }

    struct Report(Vec<String>);

    impl Report {
        fn check(&mut self, ok: bool, what: &str) {
            println!("{} {what}", if ok { "ok  " } else { "FAIL" });
            if !ok {
                self.0.push(what.to_string());
            }
        }
    }

    /// The download of `suffix` in the browser's list, as the renderer sees it.
    async fn listed(
        app: &AppHandle,
        main: &WebviewWindow,
        browser: &str,
        suffix: &str,
    ) -> Option<Value> {
        let list = hostbrowser::hostbrowser_downloads_list(
            app.clone(),
            main.clone(),
            Some(browser.to_string()),
        )
        .await
        .ok()?;
        list.as_array()?
            .iter()
            .find(|item| {
                item["url"]
                    .as_str()
                    .is_some_and(|url| url.ends_with(suffix))
            })
            .cloned()
    }

    /// Poll the list until the download of `suffix` satisfies `done`.
    async fn listed_when(
        app: &AppHandle,
        main: &WebviewWindow,
        browser: &str,
        suffix: &str,
        within: Duration,
        done: impl Fn(&Value) -> bool,
    ) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if let Some(item) = listed(app, main, browser, suffix)
                .await
                .filter(|item| done(item))
            {
                return Some(item);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The host browser commands end to end, on a local (direct) route.
    async fn drive_commands(
        app: AppHandle,
        main: WebviewWindow,
        base: String,
        report: &mut Report,
    ) {
        let second = Duration::from_secs(1);
        let browser = "probe-browser";
        // A browser opens only for a panel that has registered its layout;
        // the panel stays hidden, so no page window is shown.
        let layout = serde_json::from_value(json!({ "browserId": browser, "visible": false, "bounds": { "x": 0, "y": 0, "width": 800, "height": 600 } })).unwrap();
        let laid_out =
            hostbrowser::hostbrowser_panel_layout(app.clone(), main.clone(), layout).await;
        report.check(
            laid_out.is_ok(),
            &format!("the panel registers its layout ({laid_out:?})"),
        );
        let open = serde_json::from_value(json!({ "browserId": browser, "embedded": true, "local": true, "hostId": "probe-host", "label": "Probe" })).unwrap();
        let opened = hostbrowser::hostbrowser_open(app.clone(), main.clone(), open).await;
        report.check(
            opened.is_ok(),
            &format!("the embedded browser opens on a local route ({opened:?})"),
        );
        let command = |value: Value| {
            hostbrowser::hostbrowser_command(
                app.clone(),
                main.clone(),
                value,
                Some(browser.to_string()),
            )
        };
        let tab = command(json!({ "type": "new-tab", "url": format!("{base}/") })).await;
        report.check(
            tab.is_ok(),
            &format!("a tab opens on the test server ({:?})", tab.as_ref().err()),
        );
        tokio::time::sleep(second).await;

        // --- byte counts in the list, then cancel -----------------------
        report.check(
            command(json!({ "type": "navigate", "url": format!("{base}/slow.bin") }))
                .await
                .is_ok(),
            "the tab navigates to the slow file",
        );
        let mut samples: Vec<(u64, u64)> = Vec::new();
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(400)).await;
            if let Some(item) = listed(&app, &main, browser, "/slow.bin")
                .await
                .filter(|item| item["status"] == "progressing")
            {
                samples.push((
                    item["received"].as_u64().unwrap_or(0),
                    item["total"].as_u64().unwrap_or(0),
                ));
            }
        }
        println!("     listed (received, total): {samples:?}");
        let grew = samples.windows(2).filter(|w| w[1].0 > w[0].0).count();
        report.check(
            grew >= 3 && samples.windows(2).all(|w| w[1].0 >= w[0].0),
            "the list shows the received bytes growing",
        );
        report.check(
            samples.last().is_some_and(|s| s.1 == SLOW_BYTES as u64),
            "the list shows the total size",
        );
        let Some(item) = listed(&app, &main, browser, "/slow.bin").await else {
            report.check(false, "the slow download is listed");
            return;
        };
        let (id, path) = (
            item["id"].as_str().unwrap_or("").to_string(),
            PathBuf::from(item["savePath"].as_str().unwrap_or("")),
        );
        report.check(
            path.is_file(),
            "the partial file is in the Downloads directory",
        );
        let asked = tokio::time::Instant::now();
        let cancel = hostbrowser::hostbrowser_downloads_command(
            app.clone(),
            main.clone(),
            json!({ "type": "cancel", "id": id }),
            Some(browser.to_string()),
        )
        .await;
        report.check(
            matches!(cancel, Ok(true)),
            &format!("the cancel command is accepted ({cancel:?})"),
        );
        let cancelled = listed_when(&app, &main, browser, "/slow.bin", 8 * second, |item| {
            item["status"] == "cancelled"
        })
        .await;
        let took = asked.elapsed();
        println!("     cancelled after {took:?}: {cancelled:?}");
        report.check(cancelled.is_some(), "the download is listed as cancelled");
        report.check(
            took < 3 * second,
            "the engine confirmed the cancel (no wait for the grace period)",
        );
        report.check(
            cancelled.as_ref().is_some_and(|item| {
                item["received"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < SLOW_BYTES as u64)
            }),
            "the cancelled record keeps how far it got",
        );
        report.check(!path.exists(), "the partial file is removed");

        // --- a PDF navigation ends as a completed download --------------
        report.check(
            command(json!({ "type": "navigate", "url": format!("{base}/doc.pdf") }))
                .await
                .is_ok(),
            "the tab navigates to the PDF",
        );
        let pdf = listed_when(&app, &main, browser, "/doc.pdf", 6 * second, |item| {
            item["status"] == "completed"
        })
        .await;
        report.check(pdf.is_some(), "the PDF is listed as a completed download");
        if let Some(pdf) = pdf {
            report.check(
                pdf["received"] == json!(PDF.len()) && pdf["total"] == json!(PDF.len()),
                "its size is recorded",
            );
            report.check(
                std::fs::read(Path::new(pdf["savePath"].as_str().unwrap_or("")))
                    .is_ok_and(|bytes| bytes == PDF),
                "the saved PDF is the served one",
            );
        }

        // --- closing the browser stops what is still running ------------
        report.check(
            command(json!({ "type": "navigate", "url": format!("{base}/slow.bin?again") }))
                .await
                .is_ok(),
            "a second slow download starts",
        );
        let running = listed_when(
            &app,
            &main,
            browser,
            "/slow.bin?again",
            6 * second,
            |item| item["received"].as_u64().is_some_and(|n| n > 0),
        )
        .await;
        report.check(running.is_some(), "it is running");
        let path = PathBuf::from(
            running
                .as_ref()
                .and_then(|item| item["savePath"].as_str())
                .unwrap_or(""),
        );
        let closed =
            hostbrowser::hostbrowser_panel_close(app.clone(), main.clone(), browser.to_string())
                .await;
        report.check(
            matches!(closed, Ok(true)),
            &format!("the browser closes ({closed:?})"),
        );
        let mut removed = false;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if !path.as_os_str().is_empty() && !path.exists() {
                removed = true;
                break;
            }
        }
        report.check(
            removed,
            "closing the browser stops its download and removes the partial file",
        );
    }

    async fn drive(
        app: AppHandle,
        window: WebviewWindow,
        base: String,
        mut events: mpsc::UnboundedReceiver<Event>,
    ) -> Report {
        let mut report = Report(Vec::new());
        let second = Duration::from_secs(1);
        let go = |path: &str| {
            window
                .navigate(format!("{base}{path}").parse().unwrap())
                .unwrap()
        };
        // The first page, and the hook that `with_webview` queued behind it.
        tokio::time::sleep(second).await;

        // --- byte progress, then a real cancel --------------------------
        go("/slow.bin");
        println!("--- engine");
        let Some(Event::Requested {
            id, path, claimed, ..
        }) = next(&mut events, 5 * second).await
        else {
            report.check(false, "the slow download is reported as requested");
            return report;
        };
        report.check(
            claimed,
            "the engine download is claimed when Tauri reports it",
        );
        let mut samples: Vec<Progress> = Vec::new();
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let id = id.clone();
            if let Some(progress) = on_main(&app, move || native::progress(&id)).await {
                samples.push(progress);
            }
        }
        println!("     progress samples: {samples:?}");
        report.check(
            samples.len() == 5,
            "progress is readable while the download runs",
        );
        report.check(
            samples.windows(2).all(|w| w[1].received >= w[0].received)
                && samples.last().is_some_and(|p| p.received > 0),
            "received bytes grow",
        );
        report.check(
            samples.iter().all(|p| p.total == SLOW_BYTES as u64),
            "the total is the response's Content-Length",
        );
        report.check(
            samples.last().is_some_and(|p| p.received < p.total),
            "the download is still running when it is cancelled",
        );

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let cancel_id = id.clone();
        let cancelled = on_main(&app, move || {
            native::cancel(&cancel_id, move || {
                let _ = done_tx.send(());
            })
        })
        .await;
        report.check(cancelled, "cancel finds the engine download");
        report.check(
            tokio::time::timeout(5 * second, done_rx)
                .await
                .is_ok_and(|r| r.is_ok()),
            "the engine confirms the cancel",
        );
        let finished = next(&mut events, 2 * second).await;
        println!("     wry after the cancel: {finished:?}");
        let size = std::fs::metadata(&path).map(|m| m.len()).ok();
        println!(
            "     file after the cancel: {size:?} bytes at {}",
            path.display()
        );
        report.check(
            size.is_none_or(|bytes| bytes < SLOW_BYTES as u64),
            "the transfer stopped early",
        );
        let release_id = id.clone();
        on_main(&app, move || native::release(&release_id)).await;
        let gone_id = id.clone();
        report.check(
            on_main(&app, move || native::progress(&gone_id))
                .await
                .is_none(),
            "a released download has no handle left",
        );

        // --- a PDF is saved, not previewed ------------------------------
        go("/doc.pdf");
        match next(&mut events, 5 * second).await {
            Some(Event::Requested {
                path, claimed, url, ..
            }) => {
                report.check(
                    claimed && url.ends_with("/doc.pdf"),
                    "an inline PDF becomes a claimed download",
                );
                let done = next(&mut events, 5 * second).await;
                report.check(matches!(&done, Some(Event::Finished { success: true, url }) if url.ends_with("/doc.pdf")), "the PDF download finishes");
                report.check(
                    std::fs::read(&path).is_ok_and(|bytes| bytes == PDF),
                    "the saved PDF is the served one",
                );
            }
            other => report.check(
                false,
                &format!("an inline PDF becomes a download (got {other:?})"),
            ),
        }

        // --- an attachment WebKit could show is saved too ---------------
        go("/note.txt");
        match next(&mut events, 5 * second).await {
            Some(Event::Requested { claimed, .. }) => {
                report.check(claimed, "a text attachment becomes a claimed download");
                let done = next(&mut events, 5 * second).await;
                report.check(
                    matches!(done, Some(Event::Finished { success: true, .. })),
                    "the attachment download finishes",
                );
            }
            other => report.check(
                false,
                &format!("a text attachment becomes a download (got {other:?})"),
            ),
        }

        // --- without the hook wry decides again -------------------------
        on_main(&app, || native::unhook_page(LABEL)).await;
        go("/doc.pdf");
        let shown = next(&mut events, 2 * second).await;
        report.check(
            shown.is_none(),
            &format!("after unhooking, the PDF is shown by the engine again (got {shown:?})"),
        );
        go("/note.txt");
        let shown = next(&mut events, 2 * second).await;
        report.check(
            shown.is_none(),
            &format!(
                "…and so is the text attachment: wry allows what WebKit can render (got {shown:?})"
            ),
        );
        go("/");
        tokio::time::sleep(second).await;
        report.check(
            window.url().is_ok_and(|url| url.path() == "/"),
            "wry's own delegate still drives navigations",
        );

        println!("--- commands");
        let main = app.get_webview_window(MAIN).expect("main window");
        drive_commands(app.clone(), main, base, &mut report).await;
        report
    }

    pub fn run() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let downloads =
            std::env::temp_dir().join(format!("netcatty-hb-probe-{}", std::process::id()));
        // The commands save into the user's Downloads directory and keep
        // their history in the data directory: give this run its own.
        let home = downloads.join("home");
        std::fs::create_dir_all(home.join("Downloads")).unwrap();
        std::env::set_var("HOME", &home);
        std::env::set_var("NETCATTY_PORTABLE_DATA_DIR", downloads.join("data"));
        let (tx, rx) = mpsc::unbounded_channel();
        let counter = Arc::new(AtomicUsize::new(0));

        let app = tauri::Builder::default()
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_opener::init())
            .setup(|app| {
                let cipher = netcatty_store::CredentialCipher::with_key([0x5a; 32]);
                app.manage(AppState::with_cipher(app.handle().clone(), cipher));
                app.manage(HostBrowserState::default());
                Ok(())
            })
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("build the app");
        let handle = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            serve(tokio::net::TcpListener::from_std(listener).unwrap()).await;
        });

        let dir = downloads.clone();
        let window =
            WebviewWindowBuilder::new(&handle, LABEL, WebviewUrl::External(base.parse().unwrap()))
                .visible(false)
                .on_download(move |webview, event| {
                    match event {
                        DownloadEvent::Requested { url, destination } => {
                            let id = format!("d{}", counter.fetch_add(1, Ordering::SeqCst));
                            let name = destination
                                .file_name()
                                .map(|n| n.to_owned())
                                .unwrap_or_else(|| "download".into());
                            let path = dir.join(format!("{id}-{}", name.to_string_lossy()));
                            *destination = path.clone();
                            let claimed = native::claim(webview.label(), url.as_str(), &id);
                            let _ = tx.send(Event::Requested {
                                id,
                                url: url.to_string(),
                                path,
                                claimed,
                            });
                        }
                        DownloadEvent::Finished { url, success, .. } => {
                            let _ = tx.send(Event::Finished {
                                url: url.to_string(),
                                success,
                            });
                        }
                        _ => {}
                    }
                    true
                })
                .build()
                .expect("build the page window");
        native::hook_page(&window);
        // The renderer window the embedded browser belongs to.
        WebviewWindowBuilder::new(&handle, MAIN, WebviewUrl::External(base.parse().unwrap()))
            .visible(false)
            .build()
            .expect("build the main window");

        let driver = handle.clone();
        tauri::async_runtime::spawn(async move {
            let report = tokio::time::timeout(
                Duration::from_secs(90),
                drive(driver.clone(), window, base, rx),
            )
            .await;
            let _ = std::fs::remove_dir_all(&downloads);
            let code = match report {
                Ok(report) if report.0.is_empty() => {
                    println!("hostbrowser_native_probe: all checks passed");
                    0
                }
                Ok(report) => {
                    println!(
                        "hostbrowser_native_probe: {} check(s) failed",
                        report.0.len()
                    );
                    1
                }
                Err(_) => {
                    println!("hostbrowser_native_probe: timed out");
                    2
                }
            };
            driver.exit(code);
        });
        let code = app.run_return(|_, _| {});
        std::process::exit(code);
    }
}
