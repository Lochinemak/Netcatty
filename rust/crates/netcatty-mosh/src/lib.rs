//! Mosh and EternalTerminal client helpers (pure planning, no PTYs).
//!
//! Both protocols run an external client in a local PTY; this crate holds
//! the logic around it, ported from the Electron bridges:
//!
//! * [`handshake`] — the Mosh SSH bootstrap: `MOSH CONNECT` sniffer, ssh /
//!   mosh-client command lines and environment (`moshHandshake.cjs`).
//! * [`prompts`] — answers saved password / passphrase prompts in the
//!   bootstrap PTY and detects prompts that need the user.
//! * [`auth`] — OpenSSH options for keys, agents and host-key policy.
//! * [`et`] — the `et` invocation (private ssh config, `-F` wrapper,
//!   askpass map).
//! * [`askpass`] — the `SSH_ASKPASS` helper logic (the Netcatty executable
//!   doubles as the helper).
//! * [`binaries`] — bundled / `PATH` lookup of `mosh-client`, `et`, `ssh`.

pub mod askpass;
pub mod auth;
pub mod binaries;
pub mod et;
pub mod handshake;
pub mod prompts;
