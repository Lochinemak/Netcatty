//! WebDAV transport against an in-memory server, including servers whose
//! `PUT` does not truncate (#2223) and Digest authentication.

mod support;

use netcatty_sync::webdav::{self, WebDavConfig};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use support::{Request, Response};

#[derive(Default)]
struct DavOptions {
    /// Overwrite in place without truncating, like the buggy servers.
    non_truncating_put: bool,
    /// Reject MOVE (forces the padded in-place path).
    no_move: bool,
    /// Require this exact Authorization header (Basic / Bearer).
    require_header: Option<String>,
    /// Require Digest auth with these credentials.
    digest: Option<(String, String)>,
}

#[derive(Default)]
struct Dav {
    files: Mutex<HashMap<String, Vec<u8>>>,
    log: Mutex<Vec<String>>,
}

fn md5_hex(s: &str) -> String {
    format!("{:x}", md5::compute(s.as_bytes()))
}

fn digest_ok(req: &Request, user: &str, pass: &str) -> bool {
    let Some(header) = req.header("authorization") else {
        return false;
    };
    let Some(rest) = header.strip_prefix("Digest ") else {
        return false;
    };
    let params: HashMap<String, String> = rest
        .split(", ")
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.trim_matches('"').to_owned()))
        .collect();
    let ha1 = md5_hex(&format!("{user}:dav:{pass}"));
    let ha2 = md5_hex(&format!("{}:{}", req.method, params["uri"]));
    let expected = md5_hex(&format!(
        "{ha1}:n0nce:{}:{}:auth:{ha2}",
        params["nc"], params["cnonce"]
    ));
    params.get("username").map(String::as_str) == Some(user)
        && params["uri"] == req.target
        && params["response"] == expected
}

async fn start(options: DavOptions) -> (String, Arc<Dav>) {
    let dav = Arc::new(Dav::default());
    let state = dav.clone();
    let base = support::serve(Arc::new(move |req: Request| {
        state
            .log
            .lock()
            .push(format!("{} {}", req.method, req.path()));
        if let Some(expected) = &options.require_header {
            if req.header("authorization") != Some(expected.as_str()) {
                return Response::new(401);
            }
        }
        if let Some((user, pass)) = &options.digest {
            if !digest_ok(&req, user, pass) {
                return Response::new(401).header(
                    "WWW-Authenticate",
                    r#"Digest realm="dav", nonce="n0nce", qop="auth", algorithm=MD5"#,
                );
            }
        }
        let path = req.path().trim_start_matches("/dav").to_owned();
        let mut files = state.files.lock();
        match req.method.as_str() {
            "PROPFIND" => {
                if files.contains_key(&path) {
                    Response::new(207).body("<multistatus/>")
                } else {
                    Response::new(404)
                }
            }
            "GET" => match files.get(&path) {
                Some(body) => Response::new(200).body(body.clone()),
                None => Response::new(404),
            },
            "PUT" => {
                let entry = files.entry(path).or_default();
                if options.non_truncating_put && entry.len() > req.body.len() {
                    entry[..req.body.len()].copy_from_slice(&req.body);
                } else {
                    *entry = req.body.clone();
                }
                Response::new(201)
            }
            "MOVE" => {
                if options.no_move {
                    return Response::new(405);
                }
                let dest = req.header("destination").unwrap_or_default();
                let dest_path = url::Url::parse(dest)
                    .unwrap()
                    .path()
                    .trim_start_matches("/dav")
                    .to_owned();
                match files.remove(&path) {
                    Some(body) => {
                        files.insert(dest_path, body);
                        Response::new(201)
                    }
                    None => Response::new(404),
                }
            }
            "DELETE" => {
                if files.remove(&path).is_some() {
                    Response::new(204)
                } else {
                    Response::new(404)
                }
            }
            _ => Response::new(405),
        }
    }))
    .await;
    (format!("{base}/dav/"), dav)
}

fn config(endpoint: &str) -> WebDavConfig {
    WebDavConfig {
        endpoint: endpoint.into(),
        auth_type: Some("basic".into()),
        username: Some("user".into()),
        password: Some("pässwörd".into()),
        ..Default::default()
    }
}

fn remote(dav: &Dav) -> String {
    String::from_utf8(dav.files.lock()["/netcatty-vault.json"].clone()).unwrap()
}

#[tokio::test]
async fn round_trip_with_basic_auth() {
    let (endpoint, dav) = start(DavOptions {
        require_header: Some(webdav::basic_auth_header("user", "pässwörd")),
        ..Default::default()
    })
    .await;
    let cfg = config(&endpoint);

    let init = webdav::initialize(&cfg).await.unwrap();
    assert_eq!(init.resource_id.as_deref(), Some("/netcatty-vault.json"));
    assert_eq!(webdav::download(&cfg).await.unwrap().synced_file, None);

    let file = json!({"meta": {"version": 2}, "payload": "c2VjcmV0"});
    webdav::upload(&cfg, &file).await.unwrap();
    assert_eq!(
        webdav::download(&cfg).await.unwrap().synced_file,
        Some(file)
    );
    assert!(!dav.files.lock().contains_key("/netcatty-vault.json.tmp"));

    webdav::delete(&cfg).await.unwrap();
    assert!(dav.files.lock().is_empty());
    webdav::delete(&cfg).await.unwrap();
}

#[tokio::test]
async fn wrong_credentials_surface_as_wrapped_errors() {
    let (endpoint, _dav) = start(DavOptions {
        require_header: Some("Basic nope".into()),
        ..Default::default()
    })
    .await;
    let err = webdav::initialize(&config(&endpoint)).await.unwrap_err();
    assert_eq!(
        err.message,
        "WebDAV initialize failed: Invalid response: 401 Unauthorized"
    );
}

#[tokio::test]
async fn non_truncating_server_without_move_gets_padded_put() {
    let (endpoint, dav) = start(DavOptions {
        non_truncating_put: true,
        no_move: true,
        ..Default::default()
    })
    .await;
    let cfg = config(&endpoint);
    let long = json!({"meta": {"v": 1}, "payload": "a-much-longer-previous-payload-value"});
    let short = json!({"meta": {"v": 2}, "payload": "short"});
    webdav::upload(&cfg, &long).await.unwrap();
    webdav::upload(&cfg, &short).await.unwrap();

    let text = remote(&dav);
    assert!(text.starts_with(&serde_json::to_string(&short).unwrap()));
    assert!(text[serde_json::to_string(&short).unwrap().len()..]
        .chars()
        .all(|c| c == ' '));
    assert_eq!(
        webdav::download(&cfg).await.unwrap().synced_file,
        Some(short)
    );
}

#[tokio::test]
async fn non_truncating_server_with_move_uses_atomic_replace() {
    let (endpoint, dav) = start(DavOptions {
        non_truncating_put: true,
        ..Default::default()
    })
    .await;
    let cfg = config(&endpoint);
    webdav::upload(&cfg, &json!({"payload": "0123456789012345678901234567890"}))
        .await
        .unwrap();
    let short = json!({"payload": "x"});
    webdav::upload(&cfg, &short).await.unwrap();
    assert_eq!(remote(&dav), serde_json::to_string(&short).unwrap());
    assert!(dav.log.lock().iter().any(|l| l.starts_with("MOVE")));
}

#[tokio::test]
async fn download_recovers_trailing_garbage() {
    let (endpoint, dav) = start(DavOptions::default()).await;
    dav.files.lock().insert(
        "/netcatty-vault.json".into(),
        br#"{"payload":"new"}payload":"old"}"#.to_vec(),
    );
    assert_eq!(
        webdav::download(&config(&endpoint))
            .await
            .unwrap()
            .synced_file,
        Some(json!({"payload": "new"}))
    );
}

#[tokio::test]
async fn digest_auth_round_trip() {
    let (endpoint, dav) = start(DavOptions {
        digest: Some(("alice".into(), "s3cret".into())),
        ..Default::default()
    })
    .await;
    let cfg = WebDavConfig {
        endpoint,
        auth_type: Some("digest".into()),
        username: Some("alice".into()),
        password: Some("s3cret".into()),
        ..Default::default()
    };
    let file = json!({"payload": "digest"});
    webdav::upload(&cfg, &file).await.unwrap();
    assert_eq!(
        webdav::download(&cfg).await.unwrap().synced_file,
        Some(file)
    );
    assert_eq!(remote(&dav), r#"{"payload":"digest"}"#);

    let bad = WebDavConfig {
        password: Some("wrong".into()),
        ..cfg
    };
    let err = webdav::initialize(&bad).await.unwrap_err();
    assert!(err.message.contains("401"), "{}", err.message);
}

#[tokio::test]
async fn bearer_token_auth() {
    let (endpoint, _dav) = start(DavOptions {
        require_header: Some("Bearer tok".into()),
        ..Default::default()
    })
    .await;
    let cfg = WebDavConfig {
        endpoint,
        auth_type: Some("token".into()),
        token: Some("tok".into()),
        ..Default::default()
    };
    webdav::initialize(&cfg).await.unwrap();
}
