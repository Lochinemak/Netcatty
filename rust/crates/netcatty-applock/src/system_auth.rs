//! System unlock: Touch ID (macOS LocalAuthentication) and Windows Hello
//! (WinRT `UserConsentVerifier`). Electron: `appLockSystemAuthBridge.cjs`
//! (+ the `NetcattyWindowsHello.exe` helper, whose WinRT calls are made
//! in-process here).

use async_trait::async_trait;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemAuthStatus {
    pub supported: bool,
    pub available: bool,
    /// `darwin` | `win32` | `unsupported`.
    pub platform: String,
    /// `Touch ID` | `Windows Hello` | `null`.
    pub label: Option<String>,
    pub reason: Option<String>,
}

impl SystemAuthStatus {
    pub fn unsupported() -> Self {
        Self {
            supported: false,
            available: false,
            platform: "unsupported".into(),
            label: None,
            reason: None,
        }
    }
}

/// `{ ok: true }` or `{ ok: false, error }` with `error` ∈
/// `cancelled | unavailable | unsupported | failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemAuthUnlock {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SystemAuthUnlock {
    pub fn ok() -> Self {
        Self { ok: true, error: None }
    }
    pub fn err(error: &str) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
        }
    }
}

#[async_trait]
pub trait SystemAuth: Send + Sync + 'static {
    async fn status(&self) -> SystemAuthStatus;
    async fn request_unlock(&self) -> SystemAuthUnlock;
}

/// `normalizeSystemAuthStatus`.
pub fn normalize_status(supported: bool, available: bool, reason: Option<String>, platform: &str) -> SystemAuthStatus {
    let (platform, label) = match platform {
        "darwin" => ("darwin", "Touch ID"),
        "win32" => ("win32", "Windows Hello"),
        _ => return SystemAuthStatus::unsupported(),
    };
    SystemAuthStatus {
        supported,
        available,
        platform: platform.into(),
        label: Some(label.into()),
        reason: reason.filter(|r| !r.is_empty()),
    }
}

/// `normalizeSystemAuthUnlockResult`: map platform result names onto the
/// renderer's error vocabulary.
pub fn normalize_unlock_error(error: &str) -> SystemAuthUnlock {
    match error {
        "Canceled" | "cancelled" | "RetriesExhausted" => SystemAuthUnlock::err("cancelled"),
        "DeviceNotPresent" | "NotConfiguredForUser" | "DisabledByPolicy" | "DeviceBusy" | "unavailable" => {
            SystemAuthUnlock::err("unavailable")
        }
        "unsupported" => SystemAuthUnlock::err("unsupported"),
        _ => SystemAuthUnlock::err("failed"),
    }
}

pub const UNLOCK_MESSAGE: &str = "Unlock Netcatty";

/// Native window handle provider for the Windows Hello dialog owner
/// (decimal HWND in Electron; the raw value here).
pub type WindowHandleProvider = Box<dyn Fn() -> Option<isize> + Send + Sync>;

/// The platform implementation.
pub struct PlatformSystemAuth {
    #[cfg_attr(not(windows), allow(dead_code))]
    window_handle: WindowHandleProvider,
}

impl PlatformSystemAuth {
    pub fn new(window_handle: WindowHandleProvider) -> Self {
        Self { window_handle }
    }
}

#[async_trait]
impl SystemAuth for PlatformSystemAuth {
    async fn status(&self) -> SystemAuthStatus {
        #[cfg(target_os = "macos")]
        {
            let available = tokio::task::spawn_blocking(macos::can_prompt)
                .await
                .unwrap_or(false);
            normalize_status(true, available, (!available).then(|| "unavailable".into()), "darwin")
        }
        #[cfg(windows)]
        {
            let (available, reason) = tokio::task::spawn_blocking(windows_hello::status)
                .await
                .unwrap_or((false, Some("failed".into())));
            normalize_status(true, available, reason, "win32")
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            SystemAuthStatus::unsupported()
        }
    }

    async fn request_unlock(&self) -> SystemAuthUnlock {
        #[cfg(target_os = "macos")]
        {
            macos::prompt(UNLOCK_MESSAGE).await
        }
        #[cfg(windows)]
        {
            let Some(hwnd) = (self.window_handle)().filter(|h| *h != 0) else {
                return SystemAuthUnlock::err("unavailable");
            };
            tokio::task::spawn_blocking(move || windows_hello::verify(hwnd, UNLOCK_MESSAGE))
                .await
                .unwrap_or_else(|_| SystemAuthUnlock::err("failed"))
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            SystemAuthUnlock::err("unsupported")
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::SystemAuthUnlock;
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// Electron `systemPreferences.canPromptTouchID()`: biometrics policy.
    pub fn can_prompt() -> bool {
        unsafe {
            let context = LAContext::new();
            context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .is_ok()
        }
    }

    /// Electron `systemPreferences.promptTouchID(reason)`. Any rejection is
    /// reported as `cancelled` (Electron only sees a localized message and
    /// does the same).
    pub async fn prompt(reason: &str) -> SystemAuthUnlock {
        let reason = reason.to_string();
        let ok = tokio::task::spawn_blocking(move || prompt_blocking(&reason))
            .await
            .unwrap_or(false);
        if ok {
            SystemAuthUnlock::ok()
        } else {
            SystemAuthUnlock::err("cancelled")
        }
    }

    /// LocalAuthentication replies on a private queue; this blocking-pool
    /// thread keeps the context alive and waits for the reply.
    fn prompt_blocking(reason: &str) -> bool {
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let tx = std::sync::Mutex::new(Some(tx));
        let context = unsafe { LAContext::new() };
        let block = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            if let Some(tx) = tx.lock().ok().and_then(|mut slot| slot.take()) {
                let _ = tx.send(success.as_bool());
            }
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str(reason),
                &block,
            );
        }
        let ok = rx.recv().unwrap_or(false);
        drop(context);
        ok
    }
}

#[cfg(windows)]
mod windows_hello {
    use super::{normalize_unlock_error, SystemAuthUnlock};
    use windows::core::HSTRING;
    use windows_future::IAsyncOperation;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;

    fn availability_name(value: UserConsentVerifierAvailability) -> &'static str {
        match value {
            UserConsentVerifierAvailability::Available => "Available",
            UserConsentVerifierAvailability::DeviceNotPresent => "DeviceNotPresent",
            UserConsentVerifierAvailability::NotConfiguredForUser => "NotConfiguredForUser",
            UserConsentVerifierAvailability::DisabledByPolicy => "DisabledByPolicy",
            UserConsentVerifierAvailability::DeviceBusy => "DeviceBusy",
            _ => "Unknown",
        }
    }

    fn verification_name(value: UserConsentVerificationResult) -> &'static str {
        match value {
            UserConsentVerificationResult::Verified => "Verified",
            UserConsentVerificationResult::DeviceNotPresent => "DeviceNotPresent",
            UserConsentVerificationResult::NotConfiguredForUser => "NotConfiguredForUser",
            UserConsentVerificationResult::DisabledByPolicy => "DisabledByPolicy",
            UserConsentVerificationResult::DeviceBusy => "DeviceBusy",
            UserConsentVerificationResult::RetriesExhausted => "RetriesExhausted",
            UserConsentVerificationResult::Canceled => "Canceled",
            _ => "Unknown",
        }
    }

    /// `(available, reason)` like the helper's `status` command.
    pub fn status() -> (bool, Option<String>) {
        match UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.join()) {
            Ok(value) => (
                value == UserConsentVerifierAvailability::Available,
                Some(availability_name(value).to_string()),
            ),
            Err(_) => (false, Some("failed".into())),
        }
    }

    /// The helper's `verify --hwnd <hwnd>`: the Hello dialog is owned by the
    /// Netcatty window so it opens in front of it.
    pub fn verify(hwnd: isize, message: &str) -> SystemAuthUnlock {
        let run = || -> windows::core::Result<UserConsentVerificationResult> {
            let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
            let operation: IAsyncOperation<UserConsentVerificationResult> = unsafe {
                interop.RequestVerificationForWindowAsync(HWND(hwnd as _), &HSTRING::from(message))?
            };
            operation.join()
        };
        match run() {
            Ok(UserConsentVerificationResult::Verified) => SystemAuthUnlock::ok(),
            Ok(other) => normalize_unlock_error(verification_name(other)),
            Err(_) => SystemAuthUnlock::err("failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_labels_per_platform() {
        let mac = normalize_status(true, true, None, "darwin");
        assert_eq!(mac.label.as_deref(), Some("Touch ID"));
        let win = normalize_status(true, false, Some("DeviceNotPresent".into()), "win32");
        assert_eq!(win.label.as_deref(), Some("Windows Hello"));
        assert_eq!(win.reason.as_deref(), Some("DeviceNotPresent"));
        assert_eq!(normalize_status(true, true, None, "linux"), SystemAuthStatus::unsupported());
        assert_eq!(normalize_status(true, true, Some(String::new()), "darwin").reason, None);
    }

    #[test]
    fn unlock_error_mapping() {
        assert_eq!(normalize_unlock_error("Canceled").error.as_deref(), Some("cancelled"));
        assert_eq!(normalize_unlock_error("RetriesExhausted").error.as_deref(), Some("cancelled"));
        assert_eq!(normalize_unlock_error("DeviceBusy").error.as_deref(), Some("unavailable"));
        assert_eq!(normalize_unlock_error("NotConfiguredForUser").error.as_deref(), Some("unavailable"));
        assert_eq!(normalize_unlock_error("unsupported").error.as_deref(), Some("unsupported"));
        assert_eq!(normalize_unlock_error("weird").error.as_deref(), Some("failed"));
    }
}
