use super::*;
use crate::host::{HostConfig, HostEvents, PluginHost};
use crate::secrets::SecretCipher;
use crate::store::tests::{make_store, pack_fixture};
use serde_json::json;

// --- fake transport ----------------------------------------------------------

#[derive(Clone)]
struct Reply {
    head: HttpHead,
    body: Vec<u8>,
}

fn ok_json(value: Value) -> Reply {
    Reply {
        head: HttpHead {
            status: 200,
            content_type: Some("application/json; charset=utf-8".into()),
            ..Default::default()
        },
        body: serde_json::to_vec(&value).unwrap(),
    }
}

fn status(code: u16) -> Reply {
    Reply {
        head: HttpHead {
            status: code,
            ..Default::default()
        },
        body: Vec::new(),
    }
}

#[derive(Default)]
struct FakeHttp {
    routes: Mutex<HashMap<String, Reply>>,
    requested: Mutex<Vec<String>>,
}

impl FakeHttp {
    fn route(&self, url: &str, reply: Reply) {
        self.routes.lock().insert(url.to_string(), reply);
    }
}

struct VecBody(Option<Vec<u8>>);

#[async_trait]
impl HttpBody for VecBody {
    async fn chunk(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.take().filter(|b| !b.is_empty()))
    }
}

#[async_trait]
impl GitHubHttp for FakeHttp {
    async fn get(&self, url: &str, _accept: &str) -> Result<(HttpHead, Box<dyn HttpBody>), String> {
        self.requested.lock().push(url.to_string());
        let reply = self
            .routes
            .lock()
            .get(url)
            .cloned()
            .ok_or_else(|| "offline".to_string())?;
        Ok((reply.head, Box::new(VecBody(Some(reply.body)))))
    }
}

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const API: &str = "https://api.github.com/repos/owner/repo";
const DOWNLOAD: &str = "https://github.com/owner/repo/releases/download/v1.0.0/plugin.ncpkg";

/// A well-formed repository with one release asset holding `package`.
fn github_with(package: &[u8]) -> Arc<FakeHttp> {
    let http = Arc::new(FakeHttp::default());
    http.route(
        API,
        ok_json(json!({ "full_name": "Owner/Repo", "private": false })),
    );
    http.route(
        &format!("{API}/releases/latest"),
        ok_json(json!({
            "tag_name": "v1.0.0", "draft": false, "prerelease": false,
            "assets": [
                { "name": "notes.txt" },
                { "id": 42, "name": "plugin.ncpkg", "state": "uploaded", "size": package.len(),
                  "browser_download_url": DOWNLOAD,
                  "digest": format!("sha256:{}", hex::encode(Sha256::digest(package))) },
            ],
        })),
    );
    http.route(
        &format!("{API}/commits/v1.0.0"),
        ok_json(json!({ "sha": COMMIT })),
    );
    http.route(
        DOWNLOAD,
        Reply {
            head: HttpHead {
                status: 302,
                location: Some(
                    "https://release-assets.githubusercontent.com/x/plugin.ncpkg?sig=1".into(),
                ),
                ..Default::default()
            },
            body: Vec::new(),
        },
    );
    http.route(
        "https://release-assets.githubusercontent.com/x/plugin.ncpkg?sig=1",
        Reply {
            head: HttpHead {
                status: 200,
                content_type: Some("application/octet-stream".into()),
                content_length: Some(package.len() as u64),
                ..Default::default()
            },
            body: package.to_vec(),
        },
    );
    http
}

fn edit_release(http: &FakeHttp, edit: impl FnOnce(&mut Value)) {
    let url = format!("{API}/releases/latest");
    let mut release: Value = serde_json::from_slice(&http.routes.lock()[&url].body).unwrap();
    edit(&mut release);
    http.route(&url, ok_json(release));
}

fn fixture_package(dir: &Path) -> Vec<u8> {
    std::fs::read(pack_fixture(dir, "browser-runtime-plugin")).unwrap()
}

async fn prepare_err(http: Arc<FakeHttp>) -> String {
    let data = tempfile::tempdir().unwrap();
    let store = make_store(data.path(), false);
    let service = GitHubInstallService::new(http);
    service
        .prepare(
            "main",
            "owner/repo",
            &data.path().join("tmp"),
            &store,
            &store.database,
        )
        .await
        .unwrap_err()
        .to_string()
}

// --- repository input --------------------------------------------------------

#[test]
fn repository_forms_resolve_to_one_identity() {
    for input in [
        "owner/repo",
        "Owner/Repo",
        "owner/repo/",
        "owner/repo.git",
        "  github.com/owner/repo  ",
        "https://github.com/owner/repo",
        "HTTPS://GitHub.com/Owner/Repo.git/",
        "http://github.com/owner/repo",
    ] {
        let parsed = parse_github_repository(input).unwrap_or_else(|_| panic!("{input}"));
        assert_eq!(parsed.repository, "owner/repo", "{input}");
        assert_eq!(parsed.origin, "https://github.com/owner/repo", "{input}");
    }
    assert_eq!(
        parse_github_repository("my-org/plugin_x.v2")
            .unwrap()
            .repository,
        "my-org/plugin_x.v2"
    );
}

#[test]
fn repository_grammar_rejects_everything_else() {
    for input in [
        "",
        "owner",
        "owner/repo/tree/main",
        "owner/repo?x=1",
        "owner/repo#readme",
        "https://user:pw@github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "https://gitlab.com/owner/repo",
        "ssh://github.com/owner/repo",
        "-owner/repo",
        "owner-/repo",
        "own--er/repo",
        "owner/re%2Fpo",
        "owner\\repo",
        "owner/..",
        "owner/.",
        "owner/.git",
        "owner/repo.git.git",
        "owner//repo",
        &format!("{}/repo", "a".repeat(40)),
        &format!("owner/{}", "r".repeat(101)),
        &format!("owner/repo{}", " ".repeat(600)),
    ] {
        assert!(
            parse_github_repository(input).is_err(),
            "{input:?} should be rejected"
        );
    }
}

// --- download policy -----------------------------------------------------------

#[test]
fn only_github_https_hosts_are_reachable() {
    assert!(assert_github_url("https://api.github.com/repos/a/b", true).is_ok());
    assert!(
        assert_github_url("https://github.com/a/b/releases/download/v1/x.ncpkg", false).is_ok()
    );
    assert!(assert_github_url("https://objects.githubusercontent.com/x", false).is_ok());
    for (url, api) in [
        ("https://github.com/a/b", true),
        ("https://api.github.com/repos/a/b", false),
        ("http://github.com/x", false),
        ("https://evil.example/x", false),
        ("https://u:p@github.com/x", false),
        ("https://github.com:8443/x", false),
        ("https://github.com/x#frag", false),
        ("https://github.com/x y", false),
        ("https://github.com/x\\y", false),
    ] {
        assert!(assert_github_url(url, api).is_err(), "{url}");
    }
}

#[test]
fn markup_content_types_are_recognised() {
    for ct in [
        "text/html",
        "text/html; charset=utf-8",
        "application/xml",
        "text/xml",
        "application/atom+xml",
        "application/xhtml+xml; q=1",
    ] {
        assert!(is_markup(ct), "{ct}");
    }
    for ct in [
        "application/json",
        "application/octet-stream",
        "application/zip",
        "application/json; profile=xml",
    ] {
        assert!(!is_markup(ct), "{ct}");
    }
}

#[test]
fn uri_components_are_encoded_like_javascript() {
    assert_eq!(encode_uri_component("v1.0.0"), "v1.0.0");
    assert_eq!(encode_uri_component("release/1 +x"), "release%2F1%20%2Bx");
    assert_eq!(encode_uri_component("版本"), "%E7%89%88%E6%9C%AC");
}

#[tokio::test]
async fn http_failures_map_to_actionable_errors() {
    let cases: Vec<(Reply, &str)> = vec![
        (status(429), "rate limit"),
        (
            Reply {
                head: HttpHead {
                    status: 403,
                    rate_limit_remaining: Some("0".into()),
                    ..Default::default()
                },
                body: vec![],
            },
            "rate limit",
        ),
        (status(403), "access denied"),
        (status(404), "not found"),
        (status(500), "HTTP 500"),
        (status(301), "moved"),
        (
            Reply {
                head: HttpHead {
                    status: 200,
                    content_type: Some("text/html".into()),
                    ..Default::default()
                },
                body: b"<html>".to_vec(),
            },
            "HTML/XML",
        ),
        (ok_json(json!([1, 2])), "expected JSON object"),
        (
            Reply {
                head: HttpHead {
                    status: 200,
                    content_length: Some(JSON_LIMIT as u64 + 1),
                    ..Default::default()
                },
                body: vec![],
            },
            "size limit",
        ),
    ];
    for (reply, needle) in cases {
        let http = FakeHttp::default();
        http.route(API, reply);
        let err = fetch_json(&http, API).await.unwrap_err();
        assert!(
            err.message.contains(needle),
            "{:?} should mention {needle}",
            err.message
        );
    }
    let offline = FakeHttp::default();
    assert!(fetch_json(&offline, API)
        .await
        .unwrap_err()
        .message
        .contains("Cannot reach GitHub"));
}

#[tokio::test]
async fn redirects_stay_on_github_and_are_bounded() {
    let http = FakeHttp::default();
    http.route(
        DOWNLOAD,
        Reply {
            head: HttpHead {
                status: 302,
                location: Some("https://evil.example/p".into()),
                ..Default::default()
            },
            body: vec![],
        },
    );
    let err = fetch_github_bytes(&http, DOWNLOAD, 1024, false)
        .await
        .unwrap_err();
    assert!(err.message.contains("outside approved HTTPS hosts"));

    let looping = FakeHttp::default();
    looping.route(
        DOWNLOAD,
        Reply {
            head: HttpHead {
                status: 302,
                location: Some(DOWNLOAD.into()),
                ..Default::default()
            },
            body: vec![],
        },
    );
    let err = fetch_github_bytes(&looping, DOWNLOAD, 1024, false)
        .await
        .unwrap_err();
    assert!(err.message.contains("Too many"));
    assert_eq!(looping.requested.lock().len(), 4);

    let big = FakeHttp::default();
    big.route(
        DOWNLOAD,
        Reply {
            head: HttpHead {
                status: 200,
                ..Default::default()
            },
            body: vec![0; 2048],
        },
    );
    assert!(fetch_github_bytes(&big, DOWNLOAD, 1024, false)
        .await
        .unwrap_err()
        .message
        .contains("size limit"));
}

// --- release resolution --------------------------------------------------------

#[tokio::test]
async fn release_problems_fail_closed() {
    let package = b"PK\x03\x04 not really".to_vec();
    let cases: Vec<(Box<dyn Fn(&FakeHttp)>, &str)> = vec![
        (
            Box::new(|h| {
                h.route(
                    API,
                    ok_json(json!({ "full_name": "owner/repo", "private": true })),
                )
            }),
            "selected public repository",
        ),
        (
            Box::new(|h| {
                h.route(
                    API,
                    ok_json(json!({ "full_name": "other/repo", "private": false })),
                )
            }),
            "selected public repository",
        ),
        (
            Box::new(|h| h.route(&format!("{API}/releases/latest"), status(404))),
            "no published stable release",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["prerelease"] = json!(true))),
            "stable GitHub release",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["tag_name"] = json!(""))),
            "stable GitHub release",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["assets"] = json!([]))),
            "no .ncpkg asset",
        ),
        (
            Box::new(|h| {
                edit_release(h, |r| {
                    let extra = r["assets"][1].clone();
                    r["assets"].as_array_mut().unwrap().push(extra);
                })
            }),
            "multiple .ncpkg assets",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["assets"][1]["name"] = json!("-bad.ncpkg"))),
            "artifact name or identity",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["assets"][1]["state"] = json!("starter"))),
            "artifact name or identity",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["assets"][1]["id"] = json!(0))),
            "artifact name or identity",
        ),
        (
            Box::new(|h| {
                edit_release(h, |r| {
                    r["assets"][1]["browser_download_url"] =
                        json!("https://github.com/other/repo/releases/download/v1.0.0/plugin.ncpkg")
                })
            }),
            "does not belong",
        ),
        (
            Box::new(|h| {
                edit_release(h, |r| {
                    r["assets"][1]["browser_download_url"] =
                        json!("https://github.com/owner/repo/releases/download/v2/plugin.ncpkg")
                })
            }),
            "does not belong",
        ),
        (
            Box::new(|h| {
                edit_release(h, |r| {
                    r["assets"][1]["browser_download_url"] = json!(format!("{DOWNLOAD}?x=1"))
                })
            }),
            "does not belong",
        ),
        (
            Box::new(|h| h.route(&format!("{API}/commits/v1.0.0"), status(404))),
            "no accessible commit",
        ),
        (
            Box::new(|h| {
                h.route(
                    &format!("{API}/commits/v1.0.0"),
                    ok_json(json!({ "sha": "nope" })),
                )
            }),
            "Invalid GitHub release identity",
        ),
        (
            Box::new(|h| {
                edit_release(h, |r| {
                    r["assets"][1]["size"] = json!(limits::ARCHIVE_BYTES + 1)
                })
            }),
            "size is invalid",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["assets"][1]["size"] = json!(3))),
            "size mismatch",
        ),
        (
            Box::new(|h| edit_release(h, |r| r["assets"][1]["digest"] = json!("sha256:00"))),
            "SHA-256 mismatch",
        ),
    ];
    for (break_it, needle) in cases {
        let http = github_with(&package);
        break_it(&http);
        let err = prepare_err(http).await;
        assert!(err.contains(needle), "{err:?} should mention {needle:?}");
    }

    let not_zip = b"<html>no</html>".to_vec();
    let err = prepare_err(github_with(&not_zip)).await;
    assert!(err.contains("Expected a .ncpkg ZIP package"), "{err}");
    // A ZIP header with invalid contents still has to pass the package validator.
    let err = prepare_err(github_with(&package)).await;
    assert!(!err.is_empty());
}

// --- prepare / install ---------------------------------------------------------

struct NoCipher;
impl SecretCipher for NoCipher {
    fn available(&self) -> bool {
        false
    }
    fn encrypt(&self, _: &str) -> PluginResult<Vec<u8>> {
        Err(PluginError::host("unavailable"))
    }
    fn decrypt(&self, _: &[u8]) -> PluginResult<String> {
        Err(PluginError::host("unavailable"))
    }
}

struct NoEvents;
impl HostEvents for NoEvents {
    fn emit(&self, _: &str, _: Value) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preview_then_install_the_reviewed_package_disabled() {
    let data = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let temp_root = data.path().join("netcatty-tmp");
    let package = fixture_package(packages.path());
    let host = PluginHost::new(HostConfig {
        user_data: data.path().to_path_buf(),
        netcatty_version: "1.2.1".into(),
        allow_advanced_plugins: false,
        node: None,
        cipher: Arc::new(NoCipher),
        events: Arc::new(NoEvents),
    })
    .unwrap();
    host.manager.initialize().await.unwrap();
    let service = GitHubInstallService::new(github_with(&package));

    let preview = service
        .prepare(
            "main",
            "https://github.com/Owner/Repo",
            &temp_root,
            &host.store,
            &host.database,
        )
        .await
        .unwrap();
    assert_eq!(preview.manifest["id"], "com.netcatty.runtime-smoke-browser");
    assert_eq!(preview.asset_name, "plugin.ncpkg");
    assert_eq!(preview.size, package.len() as u64);
    assert_eq!(
        preview.archive_sha256,
        hex::encode(Sha256::digest(&package))
    );
    assert_eq!(preview.source.kind, "github");
    assert_eq!(preview.source.tag.as_deref(), Some("v1.0.0"));
    assert_eq!(preview.source.commit.as_deref(), Some(COMMIT));
    assert_eq!(preview.source.asset_id, Some(42));
    let json = serde_json::to_value(&preview).unwrap();
    assert!(json.get("archiveSha256").is_some() && json.get("assetName").is_some());
    let directory = service.pending_directory("main").unwrap();
    assert!(directory.starts_with(&temp_root));
    assert!(directory.join("package.ncpkg").exists());

    // Another window cannot use this window's token.
    assert!(service
        .install("other", &preview.token, &host.manager)
        .await
        .unwrap_err()
        .to_string()
        .contains("expired"));
    assert!(service
        .install("main", "wrong-token", &host.manager)
        .await
        .is_err());

    let installed = service
        .install("main", &preview.token, &host.manager)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(installed.id, "com.netcatty.runtime-smoke-browser");
    assert!(!installed.enabled, "GitHub installs start disabled");
    let bound = host.database.get_plugin_source(&installed.id).unwrap();
    assert_eq!(bound.id, preview.source.id);
    assert_eq!(bound.asset_id, Some(42));
    // The preview is consumed and its files removed.
    assert!(!directory.exists());
    assert!(service
        .install("main", &preview.token, &host.manager)
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_package_changed_after_review_is_not_installed() {
    let data = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let package = fixture_package(packages.path());
    let host = PluginHost::new(HostConfig {
        user_data: data.path().to_path_buf(),
        netcatty_version: "1.2.1".into(),
        allow_advanced_plugins: false,
        node: None,
        cipher: Arc::new(NoCipher),
        events: Arc::new(NoEvents),
    })
    .unwrap();
    host.manager.initialize().await.unwrap();
    let service = GitHubInstallService::new(github_with(&package));
    let preview = service
        .prepare(
            "main",
            "owner/repo",
            &data.path().join("tmp"),
            &host.store,
            &host.database,
        )
        .await
        .unwrap();

    // Swap the reviewed file for another valid package.
    let other = tempfile::tempdir().unwrap();
    let replacement = pack_fixture(other.path(), "local-logging-plugin");
    std::fs::copy(
        &replacement,
        service
            .pending_directory("main")
            .unwrap()
            .join("package.ncpkg"),
    )
    .unwrap();
    let err = service
        .install("main", &preview.token, &host.manager)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("changed after preview"), "{err}");
    assert!(host
        .database
        .get_active_plugin("com.netcatty.runtime-smoke-browser")
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn previews_are_per_owner_bounded_and_discardable() {
    let data = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let package = fixture_package(packages.path());
    let store = make_store(data.path(), false);
    let temp_root = data.path().join("tmp");
    let service = GitHubInstallService::new(github_with(&package));

    let first = service
        .prepare("main", "owner/repo", &temp_root, &store, &store.database)
        .await
        .unwrap();
    let first_dir = service.pending_directory("main").unwrap();
    // A new prepare in the same window replaces the old preview.
    let second = service
        .prepare("main", "owner/repo", &temp_root, &store, &store.database)
        .await
        .unwrap();
    assert_ne!(first.token, second.token);
    assert!(!first_dir.exists());

    // Discarding with a stale token keeps the current preview.
    service.discard("main", Some(&first.token));
    assert!(service.pending_directory("main").is_some());
    service.discard("main", Some(&second.token));
    assert!(service.pending_directory("main").is_none());

    for i in 0..MAX_PENDING_OPERATIONS {
        service
            .prepare(
                &format!("w{i}"),
                "owner/repo",
                &temp_root,
                &store,
                &store.database,
            )
            .await
            .unwrap();
    }
    let err = service
        .prepare(
            "one-more",
            "owner/repo",
            &temp_root,
            &store,
            &store.database,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already active"));
}

/// Real GitHub through the reqwest transport (network; run with
/// `cargo test -p netcatty-plugins github -- --ignored`). The upstream
/// repository publishes app builds, not a `.ncpkg`, so prepare must stop at
/// the asset check after reading the repository, release and nothing else.
#[tokio::test]
#[ignore = "needs network access to api.github.com"]
async fn real_github_without_a_package_asset_fails_closed() {
    let data = tempfile::tempdir().unwrap();
    let store = make_store(data.path(), false);
    let service = GitHubInstallService::new(Arc::new(ReqwestGitHubHttp::new().unwrap()));
    let err = service
        .prepare(
            "main",
            "https://github.com/binaricat/Netcatty",
            &data.path().join("tmp"),
            &store,
            &store.database,
        )
        .await
        .unwrap_err()
        .to_string();
    eprintln!("real GitHub answered: {err}");
    assert!(
        err.contains("no .ncpkg asset") || err.contains("rate limit"),
        "{err}"
    );
    assert!(
        !data.path().join("tmp").exists(),
        "nothing is written before the package is downloaded"
    );
}
