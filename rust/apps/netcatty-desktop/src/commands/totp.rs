//! TOTP preview for the host editor (Electron: `totpBridge.cjs` +
//! `domain/totp.shared.cjs`). Same parsing rules and error codes as the
//! shared module, so the renderer's messages match: `empty`, `migration`,
//! `invalid-uri`, `hotp`, `unsupported-type`, `missing-secret`,
//! `invalid-secret`, `invalid-algorithm`, `invalid-digits`, `invalid-period`.
//!
//! Screen QR scanning (`scanTotpQrFromScreen`) is not ported.

use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const MIN_SECRET_BYTES: usize = 10;
const MAX_SECRET_BYTES: usize = 128;
const MAX_INPUT_LENGTH: usize = 4096;

/// `encodeURIComponent`.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTotp {
    secret: Vec<u8>,
    algorithm: String,
    digits: u32,
    period: u64,
    issuer: String,
    label: String,
    uri: String,
}

pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input
        .trim_end_matches('=')
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        return None;
    }
    let (mut bits, mut value, mut out) = (0u32, 0u32, Vec::new());
    for c in cleaned.bytes() {
        let index = BASE32_ALPHABET.iter().position(|b| *b == c)? as u32;
        value = (value << 5) | index;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((value >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

pub fn encode_base32(bytes: &[u8]) -> String {
    let (mut bits, mut value, mut out) = (0u32, 0u32, String::new());
    for byte in bytes {
        value = (value << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((value >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn hmac_digest(algorithm: &str, key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    fn run<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
        let mut mac = <M as KeyInit>::new_from_slice(key).ok()?;
        mac.update(message);
        Some(mac.finalize().into_bytes().to_vec())
    }
    match algorithm {
        "SHA1" => run::<Hmac<sha1::Sha1>>(key, message),
        "SHA256" => run::<Hmac<sha2::Sha256>>(key, message),
        "SHA512" => run::<Hmac<sha2::Sha512>>(key, message),
        _ => None,
    }
}

pub fn generate(parsed: &ParsedTotp, timestamp_ms: u64) -> Option<String> {
    let counter = timestamp_ms / 1000 / parsed.period;
    let hash = hmac_digest(&parsed.algorithm, &parsed.secret, &counter.to_be_bytes())?;
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    let code = binary % 10u32.pow(parsed.digits);
    Some(format!("{code:0width$}", width = parsed.digits as usize))
}

fn build_uri(p: &ParsedTotp) -> String {
    let account = if !p.label.is_empty() {
        p.label.clone()
    } else if !p.issuer.is_empty() {
        p.issuer.clone()
    } else {
        "TOTP".into()
    };
    let path_label = if !p.issuer.is_empty()
        && !p.label.is_empty()
        && !p.label.starts_with(&format!("{}:", p.issuer))
    {
        format!("{}:{}", p.issuer, p.label)
    } else {
        account
    };
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("secret", &encode_base32(&p.secret))
        .append_pair("algorithm", &p.algorithm)
        .append_pair("digits", &p.digits.to_string())
        .append_pair("period", &p.period.to_string());
    if !p.issuer.is_empty() {
        query.append_pair("issuer", &p.issuer);
    }
    format!(
        "otpauth://totp/{}?{}",
        utf8_percent_encode(&path_label, COMPONENT),
        query.finish()
    )
}

fn finalize(mut parsed: ParsedTotp) -> Result<ParsedTotp, &'static str> {
    parsed.uri = build_uri(&parsed);
    Ok(parsed)
}

fn valid_secret(secret: Option<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    match secret {
        Some(s) if (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&s.len()) => Ok(s),
        _ => Err("invalid-secret"),
    }
}

/// JS `Number(text)` integer check for an optional query value.
fn int_param(value: Option<String>, default: i64) -> Option<i64> {
    match value {
        None => Some(default),
        Some(v) if v.trim().is_empty() => Some(default),
        Some(v) => {
            let n: f64 = v.trim().parse().ok()?;
            (n.fract() == 0.0 && n.is_finite()).then_some(n as i64)
        }
    }
}

fn parse_otpauth(text: &str) -> Result<ParsedTotp, &'static str> {
    let url = url::Url::parse(text).map_err(|_| "invalid-uri")?;
    let kind = url.host_str().unwrap_or("").to_ascii_lowercase();
    match kind.as_str() {
        "" => return Err("invalid-uri"),
        "hotp" => return Err("hotp"),
        "totp" => {}
        _ => return Err("unsupported-type"),
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    let secret_param = param("secret")
        .filter(|s| !s.trim().is_empty())
        .ok_or("missing-secret")?;
    let secret = valid_secret(decode_base32(&secret_param))?;
    let algorithm = param("algorithm")
        .unwrap_or_else(|| "SHA1".into())
        .replace('-', "")
        .to_ascii_uppercase();
    if !matches!(algorithm.as_str(), "SHA1" | "SHA256" | "SHA512") {
        return Err("invalid-algorithm");
    }
    let digits = int_param(param("digits"), 6)
        .filter(|d| (6..=8).contains(d))
        .ok_or("invalid-digits")?;
    let period = int_param(param("period"), 30)
        .filter(|p| (1..=300).contains(p))
        .ok_or("invalid-period")?;

    let raw_label = percent_encoding::percent_decode_str(url.path().trim_start_matches('/'))
        .decode_utf8_lossy()
        .trim()
        .to_owned();
    let mut issuer = param("issuer").unwrap_or_default().trim().to_owned();
    let mut label = raw_label.clone();
    if issuer.is_empty() {
        if let Some((head, tail)) = raw_label.split_once(':') {
            issuer = head.trim().to_owned();
            label = tail.trim().to_owned();
        }
    } else if raw_label
        .to_lowercase()
        .starts_with(&format!("{}:", issuer.to_lowercase()))
    {
        label = raw_label[issuer.len() + 1..].trim().to_owned();
    }
    finalize(ParsedTotp {
        secret,
        algorithm,
        digits: digits as u32,
        period: period as u64,
        issuer,
        label,
        uri: String::new(),
    })
}

pub fn parse_input(input: &str) -> Result<ParsedTotp, &'static str> {
    let text = input.trim();
    if text.is_empty() {
        return Err("empty");
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("otpauth-migration:") {
        return Err("migration");
    }
    if lower.starts_with("otpauth:") {
        return parse_otpauth(text);
    }
    finalize(ParsedTotp {
        secret: valid_secret(decode_base32(text))?,
        algorithm: "SHA1".into(),
        digits: 6,
        period: 30,
        issuer: String::new(),
        label: String::new(),
        uri: String::new(),
    })
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TotpPreview {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_remaining: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn error(code: &str) -> TotpPreview {
    TotpPreview {
        ok: false,
        error: Some(code.into()),
        ..Default::default()
    }
}

pub fn preview(text: &str, timestamp_ms: u64) -> TotpPreview {
    let parsed = match parse_input(text) {
        Ok(parsed) => parsed,
        Err(code) => return error(code),
    };
    let Some(code) = generate(&parsed, timestamp_ms) else {
        return error("invalid-algorithm");
    };
    let period_ms = parsed.period * 1000;
    let into = timestamp_ms % period_ms;
    let remaining_ms = if into == 0 {
        period_ms
    } else {
        period_ms - into
    };
    TotpPreview {
        ok: true,
        uri: Some(parsed.uri),
        code: Some(code),
        seconds_remaining: Some(remaining_ms.div_ceil(1000)),
        period: Some(parsed.period),
        algorithm: Some(parsed.algorithm),
        digits: Some(parsed.digits),
        issuer: Some(parsed.issuer),
        label: Some(parsed.label),
        error: None,
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct PreviewPayload {
    text: Option<String>,
    uri: Option<String>,
}

#[tauri::command]
pub fn totp_preview(payload: Option<PreviewPayload>) -> TotpPreview {
    let payload = payload.unwrap_or_default();
    match payload.text.or(payload.uri) {
        Some(text) if text.len() <= MAX_INPUT_LENGTH => {
            preview(&text, netcatty_core::ids::now_ms().max(0) as u64)
        }
        _ => error("invalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 test secret "12345678901234567890" (SHA1).
    const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors() {
        let parsed = parse_input(&format!(
            "otpauth://totp/x?secret={RFC_SECRET_B32}&digits=8"
        ))
        .unwrap();
        assert_eq!(generate(&parsed, 59_000).as_deref(), Some("94287082"));
        assert_eq!(
            generate(&parsed, 1_111_111_109_000).as_deref(),
            Some("07081804")
        );
        assert_eq!(
            generate(&parsed, 20_000_000_000_000).as_deref(),
            Some("65353130")
        );
    }

    #[test]
    fn base32_round_trips() {
        let bytes = b"12345678901234567890";
        assert_eq!(encode_base32(bytes), RFC_SECRET_B32);
        assert_eq!(
            decode_base32(&format!("{} ==", RFC_SECRET_B32.to_lowercase())).unwrap(),
            bytes
        );
        assert!(decode_base32("01!").is_none());
    }

    #[test]
    fn error_codes_match_the_shared_module() {
        assert_eq!(parse_input("  ").unwrap_err(), "empty");
        assert_eq!(
            parse_input("otpauth-migration://offline?data=x").unwrap_err(),
            "migration"
        );
        assert_eq!(
            parse_input("otpauth://hotp/x?secret=AAAA").unwrap_err(),
            "hotp"
        );
        assert_eq!(
            parse_input("otpauth://foo/x").unwrap_err(),
            "unsupported-type"
        );
        assert_eq!(
            parse_input("otpauth://totp/x").unwrap_err(),
            "missing-secret"
        );
        assert_eq!(
            parse_input("otpauth://totp/x?secret=AAAA").unwrap_err(),
            "invalid-secret"
        );
        let base = format!("otpauth://totp/x?secret={RFC_SECRET_B32}");
        assert_eq!(
            parse_input(&format!("{base}&algorithm=MD5")).unwrap_err(),
            "invalid-algorithm"
        );
        assert_eq!(
            parse_input(&format!("{base}&digits=5")).unwrap_err(),
            "invalid-digits"
        );
        assert_eq!(
            parse_input(&format!("{base}&period=301")).unwrap_err(),
            "invalid-period"
        );
        assert_eq!(parse_input("not base32!").unwrap_err(), "invalid-secret");
    }

    #[test]
    fn labels_issuers_and_canonical_uri() {
        let parsed = parse_input(&format!(
            "otpauth://totp/ACME%20Co:alice@example.com?secret={RFC_SECRET_B32}&algorithm=sha-256"
        ))
        .unwrap();
        assert_eq!(parsed.issuer, "ACME Co");
        assert_eq!(parsed.label, "alice@example.com");
        assert_eq!(parsed.algorithm, "SHA256");
        // Same code as domain/totp.shared.cjs for this input at t = 59 s.
        assert_eq!(generate(&parsed, 59_000).as_deref(), Some("247374"));
        assert_eq!(
            parsed.uri,
            format!("otpauth://totp/ACME%20Co%3Aalice%40example.com?secret={RFC_SECRET_B32}&algorithm=SHA256&digits=6&period=30&issuer=ACME+Co")
        );

        let raw = preview(RFC_SECRET_B32, 59_000);
        assert!(raw.ok);
        assert_eq!(raw.code.as_deref(), Some("287082"));
        assert_eq!(raw.seconds_remaining, Some(1));
        assert_eq!(
            raw.uri.as_deref(),
            Some(
                format!(
                    "otpauth://totp/TOTP?secret={RFC_SECRET_B32}&algorithm=SHA1&digits=6&period=30"
                )
                .as_str()
            )
        );
    }
}
