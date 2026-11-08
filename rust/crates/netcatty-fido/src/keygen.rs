//! FIDO2 (sk-*) key pair generation through `ssh-keygen`
//! (Electron `fidoSshKeygen.cjs`). The device creates the credential (touch,
//! and PIN when required) through the askpass bridge; the handle file is
//! written to a private temp directory, read back and removed.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

const KEYGEN_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkKeygenOptions {
    /// `ED25519-SK` | `ECDSA-SK`.
    #[serde(rename = "type")]
    pub key_type: String,
    pub comment: Option<String>,
    pub resident: Option<bool>,
    pub verify_required: Option<bool>,
}

/// Same shape as `generateKeyPair`'s result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkKeygenResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SkKeygenResult {
    fn failure(error: String) -> Self {
        Self {
            success: false,
            error: Some(error),
            ..Default::default()
        }
    }
}

pub fn is_sk_key_type(key_type: &str) -> bool {
    matches!(key_type, "ED25519-SK" | "ECDSA-SK")
}

/// `ssh-keygen` arguments (empty passphrase on the handle file: the PIN
/// lives on the device).
pub fn keygen_args(options: &SkKeygenOptions, key_path: &Path) -> Vec<String> {
    let kind = if options.key_type == "ECDSA-SK" { "ecdsa-sk" } else { "ed25519-sk" };
    let comment = options
        .comment
        .clone()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "netcatty-fido-key".to_string());
    let mut args = vec![
        "-t".to_string(),
        kind.to_string(),
        "-f".to_string(),
        key_path.to_string_lossy().into_owned(),
        "-C".to_string(),
        comment,
        "-N".to_string(),
        String::new(),
    ];
    if options.resident == Some(true) {
        args.extend(["-O".to_string(), "resident".to_string()]);
    }
    if options.verify_required == Some(true) {
        args.extend(["-O".to_string(), "verify-required".to_string()]);
    }
    args
}

fn failure_hint(stderr: &str) -> &'static str {
    let lower = stderr.to_lowercase();
    let needs_hint = ["provider", "fido", "sk_", "feature not supported", "invalid format", "device not found", "no such file"]
        .iter()
        .any(|needle| lower.contains(needle));
    if needs_hint {
        " Ensure OpenSSH is built with libfido2 (macOS: brew install openssh libfido2) and a FIDO2 key is plugged in."
    } else {
        ""
    }
}

/// Run `ssh-keygen` with `askpass_env` (already carrying a lease).
pub async fn generate(
    options: &SkKeygenOptions,
    temp_base: &Path,
    ssh_keygen: &str,
    askpass_env: &[(String, String)],
) -> SkKeygenResult {
    if let Err(e) = std::fs::create_dir_all(temp_base) {
        return SkKeygenResult::failure(format!("FIDO2 key generation requires Netcatty temp directory: {e}"));
    }
    let dir = temp_base.join(format!(
        "netcatty-fido-keygen-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if let Err(e) = builder.create(&dir) {
        return SkKeygenResult::failure(format!("FIDO2 key generation requires Netcatty temp directory: {e}"));
    }
    struct Cleanup<'a>(&'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0);
        }
    }
    let _cleanup = Cleanup(&dir);
    let stem = if options.key_type == "ECDSA-SK" { "id_ecdsa_sk" } else { "id_ed25519_sk" };
    let key_path = dir.join(format!("{stem}_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));

    let mut cmd = tokio::process::Command::new(ssh_keygen);
    cmd.args(keygen_args(options, &key_path))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in askpass_env {
        cmd.env(k, v);
    }
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let output = match tokio::time::timeout(KEYGEN_TIMEOUT, cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            let msg = e.to_string();
            return SkKeygenResult::failure(format!("FIDO2 key generation failed: {msg}.{}", failure_hint(&msg)));
        }
        Err(_) => return SkKeygenResult::failure("FIDO2 key generation failed: timed out.".into()),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stderr = if stderr.is_empty() { format!("ssh-keygen exited with {}", output.status) } else { stderr };
        return SkKeygenResult::failure(format!("FIDO2 key generation failed: {stderr}.{}", failure_hint(&stderr)));
    }
    let private_key = std::fs::read_to_string(&key_path);
    let public_key = std::fs::read_to_string(format!("{}.pub", key_path.display()));
    match (private_key, public_key) {
        (Ok(private_key), Ok(public_key)) => SkKeygenResult {
            success: true,
            private_key: Some(private_key),
            public_key: Some(public_key.trim().to_string()),
            key_type: Some(if options.key_type == "ECDSA-SK" { "ECDSA-SK" } else { "ED25519-SK" }.into()),
            error: None,
        },
        (Err(e), _) | (_, Err(e)) => SkKeygenResult::failure(format!("FIDO2 key generation failed: {e}.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_per_options() {
        let path = Path::new("/t/id");
        let opts = SkKeygenOptions {
            key_type: "ECDSA-SK".into(),
            comment: Some("me@host".into()),
            resident: Some(true),
            verify_required: Some(true),
        };
        assert_eq!(
            keygen_args(&opts, path),
            ["-t", "ecdsa-sk", "-f", "/t/id", "-C", "me@host", "-N", "", "-O", "resident", "-O", "verify-required"]
        );
        let opts = SkKeygenOptions {
            key_type: "ED25519-SK".into(),
            ..Default::default()
        };
        assert_eq!(keygen_args(&opts, path), ["-t", "ed25519-sk", "-f", "/t/id", "-C", "netcatty-fido-key", "-N", ""]);
    }

    #[test]
    fn hint_only_for_provider_errors() {
        assert!(!failure_hint("Key enrollment failed: device not found").is_empty());
        assert!(failure_hint("Key enrollment failed: invalid PIN").is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failing_keygen_reports_stderr_and_cleans_up() {
        let base = tempfile::tempdir().unwrap();
        let script = base.path().join("fake-keygen");
        std::fs::write(&script, "#!/bin/sh\necho 'Key enrollment failed: device not found' >&2\nexit 1\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let work = base.path().join("work");
        let result = generate(
            &SkKeygenOptions { key_type: "ED25519-SK".into(), ..Default::default() },
            &work,
            &script.to_string_lossy(),
            &[],
        )
        .await;
        assert!(!result.success);
        let error = result.error.unwrap();
        assert!(error.starts_with("FIDO2 key generation failed: Key enrollment failed: device not found."), "{error}");
        assert!(error.contains("libfido2"));
        assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_keygen_returns_files() {
        let base = tempfile::tempdir().unwrap();
        let script = base.path().join("fake-keygen");
        // Write `<-f path>` and `<path>.pub` like ssh-keygen would.
        std::fs::write(
            &script,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -f ]; then f=$2; fi; shift; done\necho PRIVATE > \"$f\"\necho 'sk-ssh-ed25519@openssh.com AAAA c' > \"$f.pub\"\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let result = generate(
            &SkKeygenOptions { key_type: "ED25519-SK".into(), ..Default::default() },
            base.path(),
            &script.to_string_lossy(),
            &[],
        )
        .await;
        assert!(result.success, "{:?}", result.error);
        assert_eq!(result.private_key.as_deref(), Some("PRIVATE\n"));
        assert_eq!(result.public_key.as_deref(), Some("sk-ssh-ed25519@openssh.com AAAA c"));
        assert_eq!(result.key_type.as_deref(), Some("ED25519-SK"));
    }
}
