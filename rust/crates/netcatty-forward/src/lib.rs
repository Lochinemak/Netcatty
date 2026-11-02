//! `netcatty-forward` — SSH port forwarding (mirrors `portForwardingBridge.cjs`).
//!
//! * **Local** (`-L`): listen on `bind:local_port`; each accepted TCP
//!   connection opens a `direct-tcpip` channel to `remote_host:remote_port`.
//! * **Remote** (`-R`): `tcpip_forward(bind, local_port)` on the server; each
//!   `forwarded-tcpip` channel (received through
//!   `SshConnection.channels.forwarded_rx`) is connected to
//!   `remote_host:remote_port` on the local network.
//! * **Dynamic** (`-D`): a SOCKS5 server on `bind:local_port`; every CONNECT
//!   request opens a `direct-tcpip` channel to the requested destination.
//!
//! The [`TunnelRegistry`] is the authoritative runtime state; it publishes
//! status and runtime events the Tauri layer forwards to the renderer.

pub mod error;
pub mod registry;
pub mod socks5;
pub mod tunnel;

pub use error::{ForwardError, ForwardResult};
pub use registry::{TunnelEvent, TunnelRegistry};
pub use tunnel::{Tunnel, TunnelSpec};
