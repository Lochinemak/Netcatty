//! OpenSSH security-key (`sk-*`) key material helpers
//! (Electron: `looksLikeSkOpenSshMaterial`, `deriveSkPublicKeyLine`,
//! `materializeSkPrivateKeyFile`, `resolveIdentityPath`).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use regex::Regex;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SK_SSH_ED25519: &str = "sk-ssh-ed25519@openssh.com";
pub const SK_ECDSA_NISTP256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

fn sk_type_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)(?:-cert-v0[01])?@openssh\.com").unwrap()
    })
}

fn openssh_private_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----").unwrap()
    })
}

/// True for sk public lines / certificates *or* sk private PEMs. The type
/// name of a private key only exists inside the base64 body (`@` is not a
/// base64 character), so the body is decoded first.
pub fn looks_like_sk_material(text: &str) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    if sk_type_re().is_match(text) {
        return true;
    }
    let Some(captures) = openssh_private_re().captures(text) else {
        return false;
    };
    let body: String = captures[1].chars().filter(|c| !c.is_whitespace()).collect();
    let Ok(bytes) = B64.decode(body) else {
        return false;
    };
    let haystack = String::from_utf8_lossy(&bytes);
    haystack.contains(SK_SSH_ED25519) || haystack.contains(SK_ECDSA_NISTP256)
}

pub fn is_sk_algorithm(algorithm: &Algorithm) -> bool {
    matches!(algorithm, Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
}

/// Public key of an (unencrypted) sk private key handle.
pub fn sk_public_key(private_key: &str) -> Option<PublicKey> {
    let key = PrivateKey::from_openssh(private_key.trim()).ok()?;
    is_sk_algorithm(&key.algorithm()).then(|| key.public_key().clone())
}

/// `type base64 netcatty-sk` for the companion `.pub` file.
pub fn derive_public_key_line(private_key: &str) -> Option<String> {
    let mut public = sk_public_key(private_key)?;
    public.set_comment("netcatty-sk");
    public.to_openssh().ok()
}

/// Wire blob (base64) of a public key / certificate line, for matching
/// agent identities.
pub fn public_key_blob(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))?;
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    // `type base64 [comment]`; tolerate a bare base64 blob.
    let blob = if first.contains('@') || first.starts_with("ssh-") || first.starts_with("ecdsa-") || first.starts_with("sk-") {
        parts.next()?
    } else {
        first
    };
    let bytes = B64.decode(blob).ok()?;
    Some(B64.encode(bytes))
}

/// The staged copy of a vault key handle (`<dir>/id_sk`, `.pub`,
/// `-cert.pub`). The directory is removed on drop.
#[derive(Debug)]
pub struct StagedKey {
    pub dir: PathBuf,
    pub key_path: PathBuf,
    pub public_line: Option<String>,
    pub certificate: Option<String>,
}

impl StagedKey {
    pub fn certificate_path(&self) -> PathBuf {
        PathBuf::from(format!("{}-cert.pub", self.key_path.display()))
    }
}

impl Drop for StagedKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())
}

/// Persist an sk private key handle (+ optional public hint / certificate)
/// in a fresh 0700 directory under `base_dir` so `ssh-add` can load it.
/// Never stages outside the Netcatty temp directory.
pub fn stage_private_key(
    base_dir: &Path,
    private_key: &str,
    public_hint: Option<&str>,
    certificate: Option<&str>,
) -> std::io::Result<StagedKey> {
    if !looks_like_sk_material(private_key) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not an OpenSSH security-key private key",
        ));
    }
    std::fs::create_dir_all(base_dir)?;
    let dir = base_dir.join(format!("netcatty-sk-key-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir)?;
    let staged = StagedKey {
        key_path: dir.join("id_sk"),
        dir,
        public_line: public_hint
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| derive_public_key_line(private_key)),
        certificate: certificate.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
    };
    let mut pem = private_key.replace("\r\n", "\n");
    if !pem.ends_with('\n') {
        pem.push('\n');
    }
    write_private(&staged.key_path, &pem)?;
    if let Some(line) = &staged.public_line {
        write_private(&staged.dir.join("id_sk.pub"), &format!("{line}\n"))?;
    }
    if let Some(cert) = &staged.certificate {
        write_private(&staged.certificate_path(), &format!("{cert}\n"))?;
    }
    Ok(staged)
}

/// Context for `%` tokens in `IdentityFile` (OpenSSH `TOKENS`).
#[derive(Debug, Clone, Default)]
pub struct IdentityContext {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub proxy_jump: String,
    pub local_username: Option<String>,
}

/// `resolveIdentityPath`: `%d %h %i %j %k %L %l %n %p %r %u %C %%`, `~`,
/// `${VAR}` / `$VAR`; relative results are made absolute.
pub fn resolve_identity_path(raw: &str, ctx: &IdentityContext) -> String {
    use sha1::{Digest, Sha1};
    let home = dirs::home_dir().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default();
    let local_hostname = hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default();
    let port = if ctx.port == 0 { 22 } else { ctx.port }.to_string();
    let local_user = ctx
        .local_username
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_default();
    let mut hasher = Sha1::new();
    hasher.update(format!("{local_hostname}{}{port}{}{}", ctx.hostname, ctx.username, ctx.proxy_jump));
    let c_hash: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    #[cfg(unix)]
    let uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    #[cfg(not(unix))]
    let uid = String::new();

    let mut out = String::new();
    let mut chars = raw.trim().chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let Some(&token) = chars.peek() else {
            out.push('%');
            break;
        };
        let value = match token {
            '%' => Some("%".to_string()),
            'd' => Some(home.clone()),
            'h' => Some(ctx.hostname.clone()),
            'i' => Some(uid.clone()),
            'j' => Some(ctx.proxy_jump.clone()),
            'k' | 'n' => Some(ctx.hostname.clone()),
            'L' => Some(local_hostname.split('.').next().unwrap_or("").to_string()),
            'l' => Some(local_hostname.clone()),
            'p' => Some(port.clone()),
            'r' => Some(ctx.username.clone()),
            'u' => Some(local_user.clone()),
            'C' => Some(c_hash.clone()),
            _ => None,
        };
        match value {
            Some(v) => {
                chars.next();
                out.push_str(&v);
            }
            None => out.push('%'),
        }
    }
    if out == "~" {
        out = home.clone();
    } else if let Some(rest) = out.strip_prefix("~/").or_else(|| out.strip_prefix("~\\")) {
        out = Path::new(&home).join(rest).to_string_lossy().into_owned();
    }
    let out = expand_env(&out);
    if out.is_empty() {
        return out;
    }
    let path = Path::new(&out);
    if path.is_absolute() {
        out
    } else {
        std::env::current_dir()
            .map(|d| d.join(path).to_string_lossy().into_owned())
            .unwrap_or(out)
    }
}

fn expand_env(input: &str) -> String {
    static BRACED: OnceLock<Regex> = OnceLock::new();
    static BARE: OnceLock<Regex> = OnceLock::new();
    let braced = BRACED.get_or_init(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());
    let bare = BARE.get_or_init(|| Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").unwrap());
    let step = braced.replace_all(input, |c: &regex::Captures<'_>| std::env::var(&c[1]).unwrap_or_default());
    bare.replace_all(&step, |c: &regex::Captures<'_>| std::env::var(&c[1]).unwrap_or_default())
        .into_owned()
}

/// Do any of these `IdentityFile` paths hold sk material (`.pub` first)?
pub fn identity_files_look_like_sk(paths: &[String], ctx: &IdentityContext) -> bool {
    paths.iter().any(|raw| {
        let path = resolve_identity_path(raw, ctx);
        if path.is_empty() {
            return false;
        }
        let candidates = if path.ends_with(".pub") {
            vec![path]
        } else {
            vec![format!("{path}.pub"), path]
        };
        candidates
            .iter()
            .filter_map(|c| std::fs::read_to_string(c).ok())
            .any(|text| looks_like_sk_material(&text))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An ED25519-SK key handle as `ssh-keygen -t ed25519-sk` writes it
    /// (the "private" part is an opaque device handle, not key material).
    pub fn ed25519_sk_private() -> String {
        use ssh_key::private::{KeypairData, SkEd25519};
        use ssh_key::public::{Ed25519PublicKey, SkEd25519 as PublicSkEd25519};
        let public = PublicSkEd25519::new(Ed25519PublicKey([7u8; 32]), "ssh:");
        let pair = SkEd25519::new(public, 0x01, vec![1u8, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let key = PrivateKey::new(KeypairData::SkEd25519(pair), "test@netcatty").unwrap();
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string()
    }

    #[test]
    fn detects_public_lines_and_certs() {
        assert!(looks_like_sk_material("sk-ssh-ed25519@openssh.com AAAA x"));
        assert!(looks_like_sk_material("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA"));
        assert!(!looks_like_sk_material("ssh-ed25519 AAAA x"));
        assert!(!looks_like_sk_material("   "));
    }

    #[test]
    fn detects_private_pem_by_decoding_the_body() {
        let pem = ed25519_sk_private();
        assert!(!pem.contains('@'));
        assert!(looks_like_sk_material(&pem));
        let soft = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ==\n-----END OPENSSH PRIVATE KEY-----\n";
        assert!(!looks_like_sk_material(soft));
    }

    #[test]
    fn derives_public_line_for_sk_handle() {
        let line = derive_public_key_line(&ed25519_sk_private()).expect("public line");
        assert!(line.starts_with("sk-ssh-ed25519@openssh.com "), "{line}");
        assert!(line.ends_with(" netcatty-sk"));
        let blob = public_key_blob(&line).unwrap();
        assert!(!blob.is_empty());
        assert_eq!(public_key_blob(&format!("{line}\n")), Some(blob));
    }

    #[test]
    fn staging_writes_private_files_and_cleans_up() {
        let base = tempfile::tempdir().unwrap();
        let staged = stage_private_key(base.path(), &ed25519_sk_private(), None, Some("sk-ssh-ed25519-cert-v01@openssh.com AAAA")).unwrap();
        assert!(staged.key_path.exists());
        assert!(staged.dir.join("id_sk.pub").exists());
        assert!(staged.certificate_path().exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&staged.key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let mode = std::fs::metadata(&staged.dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        let dir = staged.dir.clone();
        drop(staged);
        assert!(!dir.exists());
        assert!(stage_private_key(base.path(), "ssh-ed25519 AAAA", None, None).is_err());
    }

    #[test]
    fn identity_path_tokens() {
        let ctx = IdentityContext {
            hostname: "example.com".into(),
            port: 2222,
            username: "alice".into(),
            ..Default::default()
        };
        let home = dirs::home_dir().unwrap().to_string_lossy().into_owned();
        assert_eq!(resolve_identity_path("~/.ssh/id_%r@%h-%p", &ctx), format!("{home}/.ssh/id_alice@example.com-2222"));
        assert_eq!(resolve_identity_path("/k/%%x", &ctx), "/k/%x");
        assert_eq!(resolve_identity_path("/k/%d", &ctx), format!("/k/{home}"));
        std::env::set_var("NETCATTY_FIDO_TEST_DIR", "/tmp/nc");
        assert_eq!(resolve_identity_path("${NETCATTY_FIDO_TEST_DIR}/id", &ctx), "/tmp/nc/id");
        assert_eq!(resolve_identity_path("$NETCATTY_FIDO_TEST_DIR/id", &ctx), "/tmp/nc/id");
        assert_eq!(resolve_identity_path("/k/%C", &ctx).len(), "/k/".len() + 40);
    }

    #[test]
    fn identity_files_probe_reads_pub_first() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_sk");
        std::fs::write(&key, "garbage").unwrap();
        let path = key.to_string_lossy().into_owned();
        assert!(!identity_files_look_like_sk(std::slice::from_ref(&path), &IdentityContext::default()));
        std::fs::write(dir.path().join("id_sk.pub"), "sk-ssh-ed25519@openssh.com AAAA x\n").unwrap();
        assert!(identity_files_look_like_sk(&[path], &IdentityContext::default()));
    }
}
