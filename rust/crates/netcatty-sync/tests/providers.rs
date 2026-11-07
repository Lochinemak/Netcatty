//! GitHub, Google and OneDrive helpers against mock endpoints.

mod support;

use netcatty_core::ErrorCode;
use netcatty_sync::{github, google, onedrive};
use serde_json::json;
use std::sync::Arc;
use support::{Request, Response};

fn client() -> reqwest::Client {
    netcatty_sync::http::client().unwrap()
}

#[tokio::test]
async fn github_device_flow() {
    let base = support::serve(Arc::new(|req: Request| {
        let form = req.form();
        match req.path() {
            "/login/device/code" => {
                assert_eq!(form["client_id"], "cid");
                assert_eq!(form["scope"], "gist read:user");
                assert_eq!(req.header("accept"), Some("application/json"));
                Response::json(
                    200,
                    json!({
                        "device_code": "dev", "user_code": "ABCD-1234",
                        "verification_uri": "https://github.com/login/device",
                        "expires_in": 900, "interval": 0
                    }),
                )
            }
            "/login/oauth/access_token" => {
                assert_eq!(
                    form["grant_type"],
                    "urn:ietf:params:oauth:grant-type:device_code"
                );
                if form["device_code"] == "dev" {
                    Response::json(
                        200,
                        json!({"access_token": "gho_x", "token_type": "bearer", "scope": "gist"}),
                    )
                } else {
                    Response::json(200, json!({"error": "authorization_pending"}))
                }
            }
            "/raw/file.json" => {
                assert_eq!(req.header("authorization"), Some("Bearer gho_x"));
                Response::new(200).body("full content")
            }
            _ => Response::new(404),
        }
    }))
    .await;
    let ep = github::Endpoints {
        device_code_url: format!("{base}/login/device/code"),
        access_token_url: format!("{base}/login/oauth/access_token"),
        gist_raw_origin: base.clone(),
    };

    let start = github::start_device_flow(&client(), &ep, "cid", None)
        .await
        .unwrap();
    assert_eq!(start.user_code.as_deref(), Some("ABCD-1234"));
    assert_eq!(start.interval, 5, "zero interval falls back to 5s");
    assert!(start.expires_at > netcatty_sync::http::now_ms());

    let token = github::poll_device_flow_token(&client(), &ep, "cid", Some("dev"))
        .await
        .unwrap();
    assert_eq!(token["access_token"], "gho_x");
    let pending = github::poll_device_flow_token(&client(), &ep, "cid", Some("other"))
        .await
        .unwrap();
    assert_eq!(pending["error"], "authorization_pending");
    assert!(github::poll_device_flow_token(&client(), &ep, "cid", None)
        .await
        .is_err());

    let raw = github::download_gist_raw(
        &client(),
        &ep,
        Some("gho_x"),
        Some(&format!("{base}/raw/file.json")),
    )
    .await
    .unwrap();
    assert_eq!(raw, "full content");
}

#[tokio::test]
async fn google_tokens_and_drive() {
    let base = support::serve(Arc::new(|req: Request| {
        let form = req.form();
        match (req.method.as_str(), req.path()) {
            ("POST", "/token") => match form.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    assert_eq!(form["code_verifier"], "ver");
                    assert_eq!(form.get("client_secret").map(String::as_str), Some("sec"));
                    Response::json(200, json!({"access_token": "at", "refresh_token": "rt", "expires_in": 3600, "token_type": "Bearer"}))
                }
                Some("refresh_token") => {
                    if form["refresh_token"] == "dead" {
                        Response::json(400, json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}))
                    } else {
                        Response::json(200, json!({"access_token": "at2", "expires_in": 3600, "token_type": "Bearer"}))
                    }
                }
                _ => Response::new(400),
            },
            ("GET", "/drive/files") => {
                assert!(req.target.contains("spaces=appDataFolder"));
                assert!(req.target.contains("netcatty-vault.json"));
                Response::json(200, json!({"files": [{"id": "fid"}]}))
            }
            ("POST", "/upload/files") => {
                let ct = req.header("content-type").unwrap().to_owned();
                assert!(ct.starts_with("multipart/related; boundary=----netcatty_"));
                let body = req.body_text();
                assert!(body.contains(r#""parents":["appDataFolder"]"#));
                assert!(body.contains("\"payload\": \"p\""), "pretty JSON content: {body}");
                Response::json(200, json!({"id": "newid"}))
            }
            ("PATCH", "/upload/files/fid") => Response::json(200, json!({"id": "fid"})),
            ("GET", "/drive/files/fid") => Response::json(200, json!({"payload": "p"})),
            ("GET", "/drive/files/gone") => Response::json(404, json!({"error": {"message": "File not found"}})),
            ("GET", "/drive/files/denied") => Response::json(401, json!({})),
            ("DELETE", "/drive/files/gone") => Response::new(404),
            ("DELETE", "/drive/files/fid") => Response::new(204),
            _ => Response::new(500).body(format!("unexpected {} {}", req.method, req.target)),
        }
    }))
    .await;
    let ep = google::Endpoints {
        token_url: format!("{base}/token"),
        userinfo_url: format!("{base}/userinfo"),
        drive_api: format!("{base}/drive"),
        drive_upload_api: format!("{base}/upload"),
    };
    let c = client();

    let tokens = google::exchange_code(
        &c,
        &ep,
        &google::ExchangeRequest {
            client_id: Some("cid".into()),
            client_secret: Some("sec".into()),
            code: Some("code".into()),
            code_verifier: Some("ver".into()),
            redirect_uri: Some("http://127.0.0.1:45678/oauth/callback".into()),
        },
    )
    .await
    .unwrap();
    assert_eq!(tokens.access_token, "at");
    assert_eq!(tokens.refresh_token.as_deref(), Some("rt"));

    let refreshed = google::refresh_token(
        &c,
        &ep,
        &google::RefreshRequest {
            client_id: Some("cid".into()),
            client_secret: None,
            refresh_token: Some("rt".into()),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        refreshed.refresh_token.as_deref(),
        Some("rt"),
        "Google keeps the input refresh token"
    );

    let err = google::refresh_token(
        &c,
        &ep,
        &google::RefreshRequest {
            client_id: Some("cid".into()),
            client_secret: None,
            refresh_token: Some("dead".into()),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.message,
        "Google token refresh failed: Token has been expired or revoked."
    );

    let missing = google::exchange_code(&c, &ep, &google::ExchangeRequest::default())
        .await
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::InvalidArgument);
    assert_eq!(missing.message, "Missing Google clientId");

    assert_eq!(
        google::find_sync_file(&c, &ep, Some("at"), None)
            .await
            .unwrap()
            .file_id
            .as_deref(),
        Some("fid")
    );
    let file = json!({"payload": "p"});
    assert_eq!(
        google::create_sync_file(&c, &ep, Some("at"), None, Some(&file))
            .await
            .unwrap()
            .file_id
            .as_deref(),
        Some("newid")
    );
    google::update_sync_file(&c, &ep, Some("at"), Some("fid"), Some(&file))
        .await
        .unwrap();
    assert_eq!(
        google::download_sync_file(&c, &ep, Some("at"), Some("fid"))
            .await
            .unwrap()
            .synced_file,
        Some(file)
    );
    assert_eq!(
        google::download_sync_file(&c, &ep, Some("at"), Some("gone"))
            .await
            .unwrap()
            .synced_file,
        None
    );
    let err = google::download_sync_file(&c, &ep, Some("at"), Some("denied"))
        .await
        .unwrap_err();
    assert_eq!(
        err.message,
        "Token expired or invalid. Please reconnect Google Drive."
    );
    google::delete_sync_file(&c, &ep, Some("at"), Some("gone"))
        .await
        .unwrap();
    google::delete_sync_file(&c, &ep, Some("at"), Some("fid"))
        .await
        .unwrap();
}

#[tokio::test]
async fn onedrive_tokens_and_graph() {
    let base_cell: Arc<std::sync::OnceLock<String>> = Arc::new(std::sync::OnceLock::new());
    let cell = base_cell.clone();
    let base = support::serve(Arc::new(move |req: Request| {
        let form = req.form();
        let base = cell.get().cloned().unwrap_or_default();
        match (req.method.as_str(), req.path()) {
            ("POST", "/token") => match form["refresh_token"].as_str() {
                "dead" => Response::json(
                    400,
                    json!({"error": "invalid_grant", "error_description": "AADSTS70008: expired"}),
                ),
                "flaky" => Response::json(503, json!({"error": "temporarily_unavailable"})),
                _ => {
                    assert!(form["scope"].contains("Files.ReadWrite.AppFolder"));
                    Response::json(200, json!({"access_token": "at", "expires_in": 3600}))
                }
            },
            ("GET", "/graph/me") => Response::json(
                200,
                json!({"id": "u1", "userPrincipalName": "a@b.c", "displayName": "A"}),
            ),
            ("GET", "/graph/me/photo/$value") => Response::new(200)
                .header("Content-Type", "image/png")
                .body(vec![1, 2, 3]),
            ("GET", "/graph/me/drive/special/approot:/netcatty-vault.json") => Response::json(
                200,
                json!({
                    "id": "item1",
                    "@microsoft.graph.downloadUrl": format!("{base}/download/item1"),
                }),
            ),
            ("PUT", "/graph/me/drive/special/approot:/netcatty-vault.json:/content") => {
                assert!(req.header("authorization").is_some());
                Response::json(201, json!({"id": "item1"}))
            }
            ("GET", "/download/item1") => {
                assert!(
                    req.header("authorization").is_none(),
                    "download URL is pre-authenticated"
                );
                Response::json(200, json!({"payload": "od"}))
            }
            ("GET", "/graph/me/drive/items/missing") => Response::new(404),
            ("DELETE", "/graph/me/drive/items/item1") => Response::new(204),
            _ => Response::new(500).body(format!("unexpected {} {}", req.method, req.target)),
        }
    }))
    .await;
    base_cell.set(base.clone()).unwrap();
    let ep = onedrive::Endpoints {
        token_url: format!("{base}/token"),
        graph_api: format!("{base}/graph"),
    };
    let c = client();
    let refresh = |token: &str| onedrive::RefreshRequest {
        client_id: Some("cid".into()),
        refresh_token: Some(token.into()),
        scope: None,
    };

    let ok = onedrive::refresh_token(&c, &ep, &refresh("live"))
        .await
        .unwrap();
    assert_eq!(
        ok.refresh_token.as_deref(),
        Some("live"),
        "old refresh token kept when not rotated"
    );

    let dead = onedrive::refresh_token(&c, &ep, &refresh("dead"))
        .await
        .unwrap_err();
    assert_eq!(
        dead.message,
        "ONEDRIVE_REAUTH_REQUIRED: OneDrive session expired, please reconnect. (AADSTS70008: expired)"
    );
    let flaky = onedrive::refresh_token(&c, &ep, &refresh("flaky"))
        .await
        .unwrap_err();
    assert_eq!(
        flaky.message,
        "OneDrive token refresh failed: temporarily_unavailable"
    );

    let user = onedrive::user_info(&c, &ep, Some("at")).await.unwrap();
    assert_eq!(user.email.as_deref(), Some("a@b.c"));
    assert_eq!(
        user.avatar_data_url.as_deref(),
        Some("data:image/png;base64,AQID")
    );

    assert_eq!(
        onedrive::find_sync_file(&c, &ep, Some("at"), None)
            .await
            .unwrap()
            .file_id
            .as_deref(),
        Some("item1")
    );
    let file = json!({"payload": "od"});
    assert_eq!(
        onedrive::upload_sync_file(&c, &ep, Some("at"), None, Some(&file))
            .await
            .unwrap()
            .file_id
            .as_deref(),
        Some("item1")
    );
    assert_eq!(
        onedrive::download_sync_file(&c, &ep, Some("at"), None, None)
            .await
            .unwrap()
            .synced_file,
        Some(file)
    );
    assert_eq!(
        onedrive::download_sync_file(&c, &ep, Some("at"), Some("missing"), None)
            .await
            .unwrap()
            .synced_file,
        None
    );
    onedrive::delete_sync_file(&c, &ep, Some("at"), Some("item1"))
        .await
        .unwrap();
}
