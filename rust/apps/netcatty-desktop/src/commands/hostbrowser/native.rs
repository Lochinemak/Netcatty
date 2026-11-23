//! Engine-side handles of host browser downloads.
//!
//! wry reports a download twice — when it starts and when it ends — and keeps
//! the engine's download object to itself, so byte progress and a real cancel
//! are out of reach through Tauri (Electron: `DownloadItem.getReceivedBytes`,
//! `getTotalBytes`, `cancel`). It also allows every response WebKit can show,
//! which displays a PDF or an `attachment` in the page instead of saving it.
//!
//! **macOS** (11.3+): a page's `WKWebView` gets a navigation delegate that
//! stands in front of wry's. It forwards every message to wry's delegate
//! (`forwardingTargetForSelector:`), and takes part in three:
//!
//! * `webView:decidePolicyForNavigationResponse:decisionHandler:` answers
//!   `Download` for the responses [`navigation_response_downloads`] names;
//!   everything else is wry's decision;
//! * the two `…didBecomeDownload:` messages are where WebKit hands over the
//!   `WKDownload`. It is remembered, then wry gets the message as before.
//!
//! When Tauri reports the download as requested, [`claim`] ties the
//! remembered `WKDownload` to the host browser's download id; [`progress`]
//! and [`cancel`] work on it from then on. Only public WebKit API is used:
//! nothing depends on wry's class names or layout.
//!
//! Everything here except [`hook_page`] must run on the main thread (the
//! handles are main-thread-only objects); off it, the functions find nothing
//! and answer `false` / `None`.
//!
//! **Windows / Linux**: not implemented. WebView2 (`DownloadStarting`) and
//! WebKitGTK (`download-started`) both expose what is needed; until they are
//! hooked, these functions are no-ops there and downloads behave as before.

use tauri::{Runtime, WebviewWindow};

/// Bytes the engine has written and expects (`0` when it does not know).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub received: u64,
    pub total: u64,
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Progress;
    use block2::{DynBlock, RcBlock};
    use netcatty_hostbrowser::navigation_response_downloads;
    use objc2::rc::{Retained, Weak};
    use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject, Sel};
    use objc2::{
        available, define_class, msg_send, sel, DefinedClass, MainThreadMarker, MainThreadOnly,
        Message,
    };
    use objc2_foundation::{ns_string, NSData, NSHTTPURLResponse, NSProgressReporting};
    use objc2_web_kit::{
        WKDownload, WKNavigationAction, WKNavigationDelegate, WKNavigationResponse,
        WKNavigationResponsePolicy, WKWebView,
    };
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use tauri::{Runtime, WebviewWindow};

    struct ProxyIvars {
        /// wry's delegate. Kept alive here: the web view only holds its
        /// delegate weakly.
        target: Retained<ProtocolObject<dyn WKNavigationDelegate>>,
        label: String,
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "NetcattyHostBrowserNavigationProxy"]
        #[ivars = ProxyIvars]
        struct NavigationProxy;

        unsafe impl NSObjectProtocol for NavigationProxy {}

        impl NavigationProxy {
            // WebKit asks which optional delegate methods exist when the
            // delegate is set: answer for wry's delegate as well.
            #[unsafe(method(respondsToSelector:))]
            fn responds_to_selector(&self, selector: Sel) -> bool {
                let own: bool = unsafe { msg_send![super(self), respondsToSelector: selector] };
                own || self.ivars().target.respondsToSelector(selector)
            }

            #[unsafe(method(forwardingTargetForSelector:))]
            fn forwarding_target(&self, _selector: Sel) -> *mut AnyObject {
                Retained::as_ptr(&self.ivars().target) as *mut AnyObject
            }
        }

        unsafe impl WKNavigationDelegate for NavigationProxy {
            #[unsafe(method(webView:decidePolicyForNavigationResponse:decisionHandler:))]
            fn response_policy(
                &self,
                webview: &WKWebView,
                response: &WKNavigationResponse,
                handler: &DynBlock<dyn Fn(WKNavigationResponsePolicy)>,
            ) {
                if response_downloads(response) {
                    handler.call((WKNavigationResponsePolicy::Download,));
                    return;
                }
                let target = &self.ivars().target;
                if target.respondsToSelector(sel!(webView:decidePolicyForNavigationResponse:decisionHandler:)) {
                    let _: () = unsafe {
                        msg_send![&**target, webView: webview, decidePolicyForNavigationResponse: response, decisionHandler: handler]
                    };
                } else {
                    handler.call((WKNavigationResponsePolicy::Allow,));
                }
            }

            #[unsafe(method(webView:navigationAction:didBecomeDownload:))]
            fn action_became_download(&self, webview: &WKWebView, action: &WKNavigationAction, download: &WKDownload) {
                remember(&self.ivars().label, download);
                let target = &self.ivars().target;
                if target.respondsToSelector(sel!(webView:navigationAction:didBecomeDownload:)) {
                    let _: () = unsafe {
                        msg_send![&**target, webView: webview, navigationAction: action, didBecomeDownload: download]
                    };
                }
            }

            #[unsafe(method(webView:navigationResponse:didBecomeDownload:))]
            fn response_became_download(
                &self,
                webview: &WKWebView,
                response: &WKNavigationResponse,
                download: &WKDownload,
            ) {
                remember(&self.ivars().label, download);
                let target = &self.ivars().target;
                if target.respondsToSelector(sel!(webView:navigationResponse:didBecomeDownload:)) {
                    let _: () = unsafe {
                        msg_send![&**target, webView: webview, navigationResponse: response, didBecomeDownload: download]
                    };
                }
            }
        }
    );

    impl NavigationProxy {
        fn new(
            mtm: MainThreadMarker,
            target: Retained<ProtocolObject<dyn WKNavigationDelegate>>,
            label: String,
        ) -> Retained<Self> {
            let this = Self::alloc(mtm).set_ivars(ProxyIvars { target, label });
            unsafe { msg_send![super(this), init] }
        }
    }

    struct Page {
        proxy: Retained<NavigationProxy>,
        webview: Weak<WKWebView>,
    }

    thread_local! {
        /// Hooked pages by window label.
        static PAGES: RefCell<HashMap<String, Page>> = RefCell::new(HashMap::new());
        /// Downloads WebKit has created that Tauri has not reported yet.
        static PENDING: RefCell<Vec<(String, Retained<WKDownload>)>> = const { RefCell::new(Vec::new()) };
        /// Running downloads by host browser download id.
        static ACTIVE: RefCell<HashMap<String, Retained<WKDownload>>> = RefCell::new(HashMap::new());
    }

    /// The URL Tauri reports for a download: wry takes the original
    /// request's `absoluteString` (`download_policy` in wry) and Tauri
    /// parses it, which may normalise it.
    fn download_url(download: &WKDownload) -> Option<String> {
        let request = unsafe { download.originalRequest() }?;
        let raw = request.URL()?.absoluteString()?.to_string();
        Some(url::Url::parse(&raw).map(String::from).unwrap_or(raw))
    }

    fn remember(label: &str, download: &WKDownload) {
        PENDING.with(|pending| {
            pending
                .borrow_mut()
                .push((label.to_string(), download.retain()))
        });
    }

    /// Should this HTTP response be saved instead of shown?
    fn response_downloads(response: &WKNavigationResponse) -> bool {
        let url_response = unsafe { response.response() };
        let Some(http) = url_response.downcast_ref::<NSHTTPURLResponse>() else {
            return false;
        };
        let mime = url_response.MIMEType().map(|mime| mime.to_string());
        let disposition = http
            .valueForHTTPHeaderField(ns_string!("Content-Disposition"))
            .map(|value| value.to_string());
        let frame = if unsafe { response.isForMainFrame() } {
            "mainFrame"
        } else {
            "subFrame"
        };
        let status = u16::try_from(http.statusCode()).unwrap_or(0);
        navigation_response_downloads(frame, status, mime.as_deref(), disposition.as_deref())
    }

    pub fn hook_page<R: Runtime>(window: &WebviewWindow<R>) {
        let label = window.label().to_string();
        let hooked = window.with_webview(move |webview| {
            // `WKDownload` and the `Download` response policy are 11.3+.
            if !available!(macos = 11.3) {
                return;
            }
            let Some(mtm) = MainThreadMarker::new() else {
                return;
            };
            let webview: &WKWebView = unsafe { &*webview.inner().cast() };
            let Some(target) = (unsafe { webview.navigationDelegate() }) else {
                return;
            };
            let proxy = NavigationProxy::new(mtm, target, label.clone());
            unsafe { webview.setNavigationDelegate(Some(ProtocolObject::from_ref(&*proxy))) };
            let page = Page {
                proxy,
                webview: Weak::new(webview),
            };
            PAGES.with(|pages| pages.borrow_mut().insert(label, page));
        });
        if let Err(err) = hooked {
            tracing::debug!(%err, "host browser page has no engine download hook");
        }
    }

    pub fn unhook_page(label: &str) {
        PENDING.with(|pending| pending.borrow_mut().retain(|(owner, _)| owner != label));
        let Some(page) = PAGES.with(|pages| pages.borrow_mut().remove(label)) else {
            return;
        };
        // Still alive (the window is torn down asynchronously): give wry's
        // delegate back rather than leave the web view without one.
        if let Some(webview) = page.webview.load() {
            unsafe { webview.setNavigationDelegate(Some(&page.proxy.ivars().target)) };
        }
    }

    pub fn claim(label: &str, url: &str, id: &str) -> bool {
        let download = PENDING.with(|pending| {
            let mut pending = pending.borrow_mut();
            let index = pending.iter().position(|(owner, download)| {
                owner == label && download_url(download).as_deref() == Some(url)
            })?;
            Some(pending.remove(index).1)
        });
        match download {
            Some(download) => {
                ACTIVE.with(|active| active.borrow_mut().insert(id.to_string(), download));
                true
            }
            None => false,
        }
    }

    pub fn discard(label: &str, url: &str) {
        PENDING.with(|pending| {
            let mut pending = pending.borrow_mut();
            if let Some(index) = pending.iter().position(|(owner, download)| {
                owner == label && download_url(download).as_deref() == Some(url)
            }) {
                pending.remove(index);
            }
        });
    }

    pub fn progress(id: &str) -> Option<Progress> {
        let download = ACTIVE.with(|active| active.borrow().get(id).cloned())?;
        let progress = download.progress();
        Some(Progress {
            received: u64::try_from(progress.completedUnitCount()).unwrap_or(0),
            total: u64::try_from(progress.totalUnitCount()).unwrap_or(0),
        })
    }

    pub fn cancel(id: &str, done: impl FnOnce() + 'static) -> bool {
        let Some(download) = ACTIVE.with(|active| active.borrow().get(id).cloned()) else {
            return false;
        };
        let done = Cell::new(Some(done));
        let block = RcBlock::new(move |_resume_data: *mut NSData| {
            if let Some(done) = done.take() {
                done();
            }
        });
        unsafe { download.cancel(Some(&block)) };
        true
    }

    pub fn release(id: &str) {
        ACTIVE.with(|active| active.borrow_mut().remove(id));
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::Progress;
    use tauri::{Runtime, WebviewWindow};

    pub fn hook_page<R: Runtime>(_window: &WebviewWindow<R>) {}
    pub fn unhook_page(_label: &str) {}
    pub fn claim(_label: &str, _url: &str, _id: &str) -> bool {
        false
    }
    pub fn discard(_label: &str, _url: &str) {}
    pub fn progress(_id: &str) -> Option<Progress> {
        None
    }
    pub fn cancel(_id: &str, _done: impl FnOnce() + 'static) -> bool {
        false
    }
    pub fn release(_id: &str) {}
}

/// Put the engine hook on a freshly built page window. Call it right after
/// `build()`; the hook is installed on the main thread.
pub fn hook_page<R: Runtime>(window: &WebviewWindow<R>) {
    imp::hook_page(window);
}

/// Forget a page (its window is being destroyed) and the downloads of it
/// that were never reported.
pub fn unhook_page(label: &str) {
    imp::unhook_page(label);
}

/// Tie the engine download of `url` in page `label` to `id`. `false` when
/// the engine handle is unknown: the download then has no byte progress and
/// cannot be stopped early.
pub fn claim(label: &str, url: &str, id: &str) -> bool {
    imp::claim(label, url, id)
}

/// Drop the remembered engine download of `url` in page `label` (the
/// download was refused, or ended before it was reported).
pub fn discard(label: &str, url: &str) {
    imp::discard(label, url);
}

/// Bytes written so far for a claimed download.
pub fn progress(id: &str) -> Option<Progress> {
    imp::progress(id)
}

/// Stop a claimed download. `done` runs on the main thread once the engine
/// has stopped writing. `false` when there is no engine handle for `id`.
pub fn cancel(id: &str, done: impl FnOnce() + 'static) -> bool {
    imp::cancel(id, done)
}

/// Let go of the engine handle of a finished download.
pub fn release(id: &str) {
    imp::release(id);
}
