//! macOS-native pieces with no Tauri API:
//!
//! * the Dock icon image (`NSApplication.applicationIconImage`), Electron
//!   `app.dock.setIcon`;
//! * the Dock menu: an `applicationDockMenu:` method added to the app
//!   delegate class at runtime (tao's delegate does not implement it), built
//!   fresh each time the user opens the menu, Electron `app.dock.setMenu`;
//! * the default URL-scheme handler (Launch Services), Electron
//!   `setAsDefaultProtocolClient` / `removeAsDefaultProtocolClient`.
//!
//! AppKit calls must run on the main thread; the functions return `false`
//! when called elsewhere.

use crate::dock::{DockAction, DockMenu};
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
use objc2::{define_class, msg_send, sel, AnyThread, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{NSApplication, NSImage, NSMenu, NSMenuItem};
use objc2_foundation::{NSArray, NSBundle, NSData, NSObject, NSString};
use std::cell::RefCell;
use std::ffi::c_void;
use std::rc::Rc;

// ---------------------------------------------------------------------------
// Dock icon
// ---------------------------------------------------------------------------

/// Replace the Dock icon with a PNG / ICNS image. Main thread only.
pub fn set_dock_icon(bytes: &[u8]) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    let data = NSData::with_bytes(bytes);
    let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) else {
        return false;
    };
    let app = NSApplication::sharedApplication(mtm);
    unsafe { app.setApplicationIconImage(Some(&image)) };
    true
}

// ---------------------------------------------------------------------------
// Dock menu
// ---------------------------------------------------------------------------

type Provider = Rc<dyn Fn() -> DockMenu>;
type Handler = Rc<dyn Fn(DockAction)>;

struct DockState {
    provider: Provider,
    handler: Handler,
    target: Retained<DockTarget>,
    /// Keeps the last returned menu alive (AppKit does not retain it).
    menu: Option<Retained<NSMenu>>,
    /// Action of each enabled item, indexed by the item's tag.
    actions: Vec<DockAction>,
}

thread_local! {
    static DOCK: RefCell<Option<DockState>> = const { RefCell::new(None) };
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NetcattyDockMenuTarget"]
    struct DockTarget;

    impl DockTarget {
        #[unsafe(method(netcattyDockAction:))]
        fn dock_action(&self, sender: &NSMenuItem) {
            dispatch(sender.tag());
        }
    }
);

impl DockTarget {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        unsafe { msg_send![Self::alloc(mtm), init] }
    }
}

fn dispatch(tag: isize) {
    let picked = DOCK.with(|cell| {
        let state = cell.borrow();
        let state = state.as_ref()?;
        let action = state.actions.get(usize::try_from(tag).ok()?)?.clone();
        Some((state.handler.clone(), action))
    });
    if let Some((handler, action)) = picked {
        handler(action);
    }
}

fn menu_item(
    mtm: MainThreadMarker,
    title: &str,
    target: Option<&DockTarget>,
    tag: Option<isize>,
) -> Retained<NSMenuItem> {
    let action = target.map(|_| sel!(netcattyDockAction:));
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &NSString::from_str(title),
            action,
            &NSString::from_str(""),
        )
    };
    if let (Some(target), Some(tag)) = (target, tag) {
        unsafe { item.setTarget(Some(target)) };
        item.setTag(tag);
        item.setEnabled(true);
    } else {
        item.setEnabled(false);
    }
    item
}

fn build_menu(mtm: MainThreadMarker, state: &mut DockState) -> Retained<NSMenu> {
    let model = (state.provider)();
    state.actions.clear();
    let menu = NSMenu::new(mtm);
    menu.setAutoenablesItems(false);

    state.actions.push(DockAction::OpenMain);
    menu.addItem(&menu_item(mtm, &model.open_main_label, Some(&state.target), Some(0)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));

    let parent = menu_item(mtm, &model.new_connection_label, None, None);
    let submenu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &NSString::from_str(&model.new_connection_label));
    submenu.setAutoenablesItems(false);
    if model.hosts.is_empty() {
        submenu.addItem(&menu_item(mtm, &model.empty_label, None, None));
    } else {
        for host in &model.hosts {
            let tag = state.actions.len() as isize;
            state.actions.push(DockAction::ConnectHost(host.id.clone()));
            submenu.addItem(&menu_item(mtm, &host.label, Some(&state.target), Some(tag)));
        }
    }
    parent.setSubmenu(Some(&submenu));
    parent.setEnabled(!model.hosts.is_empty());
    menu.addItem(&parent);
    menu
}

extern "C-unwind" fn application_dock_menu(_this: *mut AnyObject, _cmd: Sel, _sender: *mut AnyObject) -> *mut NSMenu {
    let Some(mtm) = MainThreadMarker::new() else {
        return std::ptr::null_mut();
    };
    DOCK.with(|cell| {
        let mut guard = cell.borrow_mut();
        let Some(state) = guard.as_mut() else {
            return std::ptr::null_mut();
        };
        let menu = build_menu(mtm, state);
        let ptr = Retained::as_ptr(&menu) as *mut NSMenu;
        state.menu = Some(menu);
        ptr
    })
}

/// Install the Dock menu. `provider` builds the menu model each time it is
/// opened; `handler` receives clicks. Main thread only.
pub fn install_dock_menu(provider: impl Fn() -> DockMenu + 'static, handler: impl Fn(DockAction) + 'static) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    let app = NSApplication::sharedApplication(mtm);
    let Some(delegate) = app.delegate() else {
        tracing::warn!("dock menu: the application has no delegate");
        return false;
    };
    let delegate_object: &AnyObject = delegate.as_ref();
    let class: &AnyClass = delegate_object.class();
    let selector = sel!(applicationDockMenu:);
    if !class.responds_to(selector) {
        let imp: Imp = unsafe {
            std::mem::transmute::<
                extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject) -> *mut NSMenu,
                Imp,
            >(application_dock_menu)
        };
        let added = unsafe {
            objc2::ffi::class_addMethod(
                class as *const AnyClass as *mut AnyClass,
                selector,
                imp,
                c"@@:@".as_ptr(),
            )
        };
        if !added.as_bool() {
            tracing::warn!("dock menu: could not add applicationDockMenu:");
            return false;
        }
        // AppKit caches which optional delegate methods exist when the
        // delegate is set; set it again so the new method is seen.
        app.setDelegate(None);
        app.setDelegate(Some(&delegate));
    }
    DOCK.with(|cell| {
        *cell.borrow_mut() = Some(DockState {
            provider: Rc::new(provider),
            handler: Rc::new(handler),
            target: DockTarget::new(mtm),
            menu: None,
            actions: Vec::new(),
        });
    });
    true
}

// ---------------------------------------------------------------------------
// Default URL-scheme handler (Launch Services)
// ---------------------------------------------------------------------------

#[link(name = "CoreServices", kind = "framework")]
extern "C" {
    fn LSSetDefaultHandlerForURLScheme(scheme: *const c_void, bundle_id: *const c_void) -> i32;
    fn LSCopyDefaultHandlerForURLScheme(scheme: *const c_void) -> *mut c_void;
    fn LSCopyAllHandlersForURLScheme(scheme: *const c_void) -> *mut c_void;
}

fn bundle_identifier() -> Option<String> {
    NSBundle::mainBundle().bundleIdentifier().map(|id| id.to_string())
}

fn ns_ptr(value: &NSString) -> *const c_void {
    value as *const NSString as *const c_void
}

/// Bundle id of the current default handler (CFString is toll-free bridged).
fn default_handler(scheme: &str) -> Option<String> {
    let scheme = NSString::from_str(scheme);
    let raw = unsafe { LSCopyDefaultHandlerForURLScheme(ns_ptr(&scheme)) };
    let owned: Option<Retained<NSString>> = unsafe { Retained::from_raw(raw.cast()) };
    owned.map(|s| s.to_string())
}

fn all_handlers(scheme: &str) -> Vec<String> {
    let scheme = NSString::from_str(scheme);
    let raw = unsafe { LSCopyAllHandlersForURLScheme(ns_ptr(&scheme)) };
    let owned: Option<Retained<NSArray<NSString>>> = unsafe { Retained::from_raw(raw.cast()) };
    owned
        .map(|arr| arr.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// Make this app the default handler of `scheme`. An unbundled binary
/// (`cargo run` / `tauri dev`) has no bundle id to register: succeed without
/// touching Launch Services so the switch still gates delivery.
pub fn set_default_url_handler(scheme: &str) -> bool {
    let Some(bundle) = bundle_identifier() else {
        return true;
    };
    let scheme_ns = NSString::from_str(scheme);
    let bundle_ns = NSString::from_str(&bundle);
    unsafe { LSSetDefaultHandlerForURLScheme(ns_ptr(&scheme_ns), ns_ptr(&bundle_ns)) == 0 }
}

/// Hand `scheme` back to another handler when this app is the default
/// (the first other registered handler, else `None`, like Electron). Not
/// being the default already counts as removed.
pub fn remove_default_url_handler(scheme: &str) -> bool {
    let Some(bundle) = bundle_identifier() else {
        return true;
    };
    if !default_handler(scheme).is_some_and(|current| current.eq_ignore_ascii_case(&bundle)) {
        return true;
    }
    let other = all_handlers(scheme)
        .into_iter()
        .find(|h| !h.eq_ignore_ascii_case(&bundle))
        .unwrap_or_else(|| "None".to_owned());
    let scheme_ns = NSString::from_str(scheme);
    let other_ns = NSString::from_str(&other);
    unsafe { LSSetDefaultHandlerForURLScheme(ns_ptr(&scheme_ns), ns_ptr(&other_ns)) == 0 }
}
