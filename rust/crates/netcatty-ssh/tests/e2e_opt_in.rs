//! Opt-in end-to-end smoke test against a real SSH server.
//!
//! Skipped unless `NETCATTY_SSH_E2E_HOST` is set. Authentication uses the
//! local ssh-agent (or `~/.ssh/id_*`), so no secrets live in this file.
//!
//! ```sh
//! NETCATTY_SSH_E2E_HOST=localhost NETCATTY_SSH_E2E_USER=$USER \
//!   CARGO_TARGET_DIR=target/agent-ssh cargo test -p netcatty-ssh --test e2e_opt_in
//! ```

use netcatty_ssh::options::{ConnectOptions, HopOptions};
use netcatty_ssh::{connect, ShellEvent, ShellOptions, UnattendedCallbacks};
use std::sync::Arc;
use std::time::Duration;

fn hop_from_env() -> Option<HopOptions> {
    let hostname = std::env::var("NETCATTY_SSH_E2E_HOST").ok()?;
    let port = std::env::var("NETCATTY_SSH_E2E_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);
    let username = std::env::var("NETCATTY_SSH_E2E_USER")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".to_string());
    Some(HopOptions {
        hostname,
        port,
        username,
        use_ssh_agent: true,
        verify_host_keys: false,
        tcp_connect_timeout: Duration::from_secs(10),
        auth_ready_timeout: Duration::from_secs(30),
        ..Default::default()
    })
}

#[tokio::test]
async fn exec_and_shell_against_real_server() {
    let Some(target) = hop_from_env() else {
        eprintln!("NETCATTY_SSH_E2E_HOST not set; skipping");
        return;
    };
    let conn = connect(
        ConnectOptions {
            target,
            ..Default::default()
        },
        Arc::new(UnattendedCallbacks),
    )
    .await
    .expect("connect");
    assert!(conn
        .server_banner
        .as_deref()
        .unwrap_or("")
        .starts_with("SSH-"));

    let out = conn
        .exec("echo netcatty-e2e", Some(Duration::from_secs(10)))
        .await
        .expect("exec");
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.stdout_lossy().trim(), "netcatty-e2e");

    let out = conn
        .exec_with_stdin(
            "cat",
            b"stdin-roundtrip".to_vec(),
            Some(Duration::from_secs(10)),
        )
        .await
        .unwrap();
    assert_eq!(out.stdout_lossy(), "stdin-roundtrip");

    let out = conn
        .exec("exit 7", Some(Duration::from_secs(10)))
        .await
        .unwrap();
    assert_eq!(out.exit_code, Some(7));

    let mut shell = conn
        .open_shell(ShellOptions::default())
        .await
        .expect("shell");
    shell.resize(120, 40).unwrap();
    shell.write("echo shell-ok; exit\n".into()).await.unwrap();
    let mut saw_output = false;
    let mut exits = 0;
    while let Some(ev) = tokio::time::timeout(Duration::from_secs(15), shell.events.recv())
        .await
        .expect("shell event")
    {
        match ev {
            ShellEvent::Data(d) => saw_output |= String::from_utf8_lossy(&d).contains("shell-ok"),
            ShellEvent::Eof => {}
            ShellEvent::Exit { .. } => {
                exits += 1;
                break;
            }
        }
    }
    assert!(saw_output, "shell output not observed");
    assert_eq!(exits, 1);

    conn.disconnect().await.unwrap();
}
