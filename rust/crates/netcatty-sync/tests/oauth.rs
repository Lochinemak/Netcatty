//! OAuth loopback callback server end to end.

use netcatty_core::ErrorCode;
use netcatty_sync::oauth::{OAuthCallbackServer, CALLBACK_PATH};
use std::time::Duration;

fn server() -> OAuthCallbackServer {
    // Port 0 → always OS-assigned, so parallel tests never collide.
    OAuthCallbackServer::new(0, Duration::from_secs(30))
}

async fn hit(url: &str) -> (u16, String) {
    let res = reqwest::get(url).await.unwrap();
    let status = res.status().as_u16();
    (status, res.text().await.unwrap())
}

#[tokio::test]
async fn resolves_with_code_and_checks_state() {
    let server = server();
    let prepared = server.prepare().await.unwrap();
    assert!(prepared.redirect_uri.starts_with("http://127.0.0.1:"));
    assert!(prepared.redirect_uri.ends_with(CALLBACK_PATH));

    // Before the renderer arms the flow, callbacks are ignored.
    let (status, body) = hit(&format!("{}?code=early", prepared.redirect_uri)).await;
    assert_eq!(status, 200);
    assert!(body.contains("Authorization Not Ready"));

    let waiter = {
        let server = server.clone();
        let sid = prepared.session_id.clone();
        tokio::spawn(async move { server.await_callback(Some("st".into()), Some(sid)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, _) = hit(&format!("http://127.0.0.1:{}/other", prepared.port)).await;
    assert_eq!(status, 404);

    let (_, body) = hit(&format!("{}?code=abc&state=st", prepared.redirect_uri)).await;
    assert!(body.contains("Authorization Complete"));
    let result = waiter.await.unwrap().unwrap();
    assert_eq!(result.code, "abc");
    assert_eq!(result.state.as_deref(), Some("st"));
    assert!(!server.is_active());
}

#[tokio::test]
async fn state_mismatch_rejects() {
    let server = server();
    let prepared = server.prepare().await.unwrap();
    let waiter = {
        let server = server.clone();
        tokio::spawn(async move { server.await_callback(Some("good".into()), None).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_, body) = hit(&format!("{}?code=abc&state=evil", prepared.redirect_uri)).await;
    assert!(body.contains("Security Check Failed"));
    let err = waiter.await.unwrap().unwrap_err();
    assert_eq!(err.message, "State mismatch - possible CSRF attack");
}

#[tokio::test]
async fn cancel_and_reprepare() {
    let server = server();
    let first = server.prepare().await.unwrap();
    let waiter = {
        let server = server.clone();
        tokio::spawn(async move { server.await_callback(None, None).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Preparing again cancels the first flow.
    let second = server.prepare().await.unwrap();
    let err = waiter.await.unwrap().unwrap_err();
    assert_eq!(err.code, ErrorCode::Cancelled);
    assert_ne!(first.session_id, second.session_id);

    // A stale session id cannot await the new flow.
    let err = server
        .await_callback(None, Some(first.session_id.clone()))
        .await
        .unwrap_err();
    assert_eq!(err.message, "OAuth flow cancelled");

    // Cancel before await: the error is reported by the next await.
    server.cancel(Some(&second.session_id));
    let err = server.await_callback(None, None).await.unwrap_err();
    assert_eq!(err.message, "OAuth flow cancelled");
    let err = server.await_callback(None, None).await.unwrap_err();
    assert_eq!(err.message, "OAuth callback server not prepared");
}

#[tokio::test]
async fn times_out() {
    let server = OAuthCallbackServer::new(0, Duration::from_millis(100));
    server.prepare().await.unwrap();
    let err = server.await_callback(None, None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
}

#[tokio::test]
async fn falls_back_to_a_free_port_when_preferred_is_busy() {
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    let server = OAuthCallbackServer::new(busy_port, Duration::from_secs(5));
    let prepared = server.prepare().await.unwrap();
    assert_ne!(prepared.port, busy_port);
    server.cancel(None);
}
