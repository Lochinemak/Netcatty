//! S3 transport against an in-memory object store that re-verifies the
//! SigV4 signature of every request.

mod support;

use netcatty_sync::s3::{self, S3Config, SigningParams};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use support::{Request, Response};

const AKID: &str = "AKIDEXAMPLE";
const SECRET: &str = "secret/key";

fn signature_ok(req: &Request) -> bool {
    let Some(auth) = req.header("authorization") else {
        return false;
    };
    let signed: Vec<&str> = auth
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .map(|s| s.split(';').collect())
        .unwrap_or_default();
    let headers = signed
        .iter()
        .map(|name| {
            (
                name.to_string(),
                req.header(name).unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let expected = s3::authorization(&SigningParams {
        method: &req.method,
        canonical_uri: req.path(),
        headers,
        payload_hash: req.header("x-amz-content-sha256").unwrap_or_default(),
        access_key_id: AKID,
        secret_access_key: SECRET,
        region: "us-east-1",
        amz_date: req.header("x-amz-date").unwrap_or_default(),
    });
    let body_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&req.body));
    expected == auth
        && req.header("x-amz-content-sha256") == Some(body_hash.as_str())
        && signed.contains(&"host")
}

async fn start(deny: bool) -> (String, Arc<Mutex<HashMap<String, Vec<u8>>>>) {
    let objects: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
    let store = objects.clone();
    let base = support::serve(Arc::new(move |req: Request| {
        if deny {
            return Response::new(403)
                .body("<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
        }
        if !signature_ok(&req) {
            return Response::new(403).body(
                "<Error><Code>SignatureDoesNotMatch</Code><Message>bad sig</Message></Error>",
            );
        }
        let key = req.path().to_owned();
        let mut objects = store.lock();
        match req.method.as_str() {
            "HEAD" | "GET" => match objects.get(&key) {
                Some(body) if req.method == "GET" => Response::new(200).body(body.clone()),
                Some(_) => Response::new(200),
                None => Response::new(404).body("<Error><Code>NoSuchKey</Code></Error>"),
            },
            "PUT" => {
                assert_eq!(req.header("content-type"), Some("application/json"));
                objects.insert(key, req.body.clone());
                Response::new(200)
            }
            "DELETE" => {
                objects.remove(&key);
                Response::new(204)
            }
            _ => Response::new(405),
        }
    }))
    .await;
    (base, objects)
}

fn config(endpoint: &str) -> S3Config {
    S3Config {
        endpoint: endpoint.into(),
        region: "us-east-1".into(),
        bucket: "vault".into(),
        access_key_id: AKID.into(),
        secret_access_key: SECRET.into(),
        prefix: Some("team".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn signed_round_trip() {
    let (endpoint, objects) = start(false).await;
    let cfg = config(&endpoint);
    assert_eq!(
        s3::initialize(&cfg).await.unwrap().resource_id.as_deref(),
        Some("team/netcatty-vault.json")
    );
    assert_eq!(s3::download(&cfg).await.unwrap().synced_file, None);

    let file = json!({"meta": {"v": 1}, "payload": "s3"});
    s3::upload(&cfg, &file).await.unwrap();
    assert!(objects
        .lock()
        .contains_key("/vault/team/netcatty-vault.json"));
    assert_eq!(s3::download(&cfg).await.unwrap().synced_file, Some(file));

    s3::delete(&cfg).await.unwrap();
    assert!(objects.lock().is_empty());
}

#[tokio::test]
async fn session_token_is_signed() {
    let (endpoint, _) = start(false).await;
    let cfg = S3Config {
        session_token: Some("tok".into()),
        ..config(&endpoint)
    };
    s3::upload(&cfg, &json!({"payload": "x"})).await.unwrap();
}

#[tokio::test]
async fn wrong_secret_and_denied_bucket() {
    let (endpoint, _) = start(false).await;
    let bad = S3Config {
        secret_access_key: "wrong".into(),
        ..config(&endpoint)
    };
    let err = s3::upload(&bad, &json!({})).await.unwrap_err();
    assert_eq!(err.message, "S3 upload failed: bad sig");

    let (endpoint, _) = start(true).await;
    let err = s3::initialize(&config(&endpoint)).await.unwrap_err();
    assert_eq!(err.message, "S3 access denied");
}
