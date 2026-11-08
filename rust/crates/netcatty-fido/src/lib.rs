//! `netcatty-fido` — FIDO2 OpenSSH security keys (`sk-ssh-ed25519@openssh.com`,
//! `sk-ecdsa-sha2-nistp256@openssh.com`), ported from Electron's
//! `fidoAgentManager.cjs`, `fidoAskpass.cjs`, `fidoPromptHandler.cjs`,
//! `fidoSignFlow.cjs`, `fidoSshKeygen.cjs` and the FIDO parts of
//! `systemSshAgent.cjs` / `sshAuthHelper.cjs`.
//!
//! Same architecture as Electron: the hardware is driven by the platform's
//! OpenSSH (libfido2 / Windows WebAuthn). Netcatty runs its own
//! `ssh-agent` with `SSH_ASKPASS` pointing at the Netcatty executable in
//! helper mode, `ssh-add`s the selected key handle and signs through the
//! agent (the SSH crate speaks the agent protocol, which already carries the
//! sk signature flags and counter). PIN, touch and recovery dialogs reach
//! the renderer through [`prompt::PromptBroker`].
//!
//! * [`sk`]: key detection, public key derivation, staging, `IdentityFile`
//!   token expansion.
//! * [`prompt`]: the prompt broker and askpass prompt classification.
//! * [`askpass`]: the askpass socket server and the helper-mode client.
//! * [`agent`]: the shared owned agent and identity reference counting.
//! * [`keygen`]: `ssh-keygen -t ed25519-sk|ecdsa-sk`.
//! * [`service`]: everything wired together for the app.

pub mod agent;
pub mod askpass;
pub mod keygen;
pub mod prompt;
pub mod service;
pub mod sk;

pub use askpass::run_helper_if_requested;
pub use keygen::{is_sk_key_type, SkKeygenOptions, SkKeygenResult};
pub use prompt::{PromptBroker, PromptSink};
pub use service::{failure_reason, FidoService, PrepareRequest, PreparedAgent, Recovery, SigningGuard};
pub use sk::{looks_like_sk_material, IdentityContext};
