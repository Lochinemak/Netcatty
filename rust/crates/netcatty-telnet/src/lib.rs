//! Telnet protocol helpers and the login-prompt auto-login detector.
//!
//! Pure logic, no I/O: the desktop app owns the sockets / serial ports and
//! feeds bytes and decoded text through these state machines. Ported from
//! `electron/bridges/telnetProtocol.cjs` and `telnetAutoLogin.cjs`; the
//! Electron unit tests are ported alongside each module.
//!
//! * [`protocol`] — RFC 854 framing ([`protocol::Parser`]), option
//!   negotiation ([`protocol::Negotiator`]) and the lazily-activated
//!   [`protocol::TelnetCodec`] that combines both for a session.
//! * [`autologin`] — answers `Username:` / `Password:` prompts with saved
//!   credentials (used by telnet and serial sessions).

pub mod autologin;
pub mod protocol;

pub use autologin::{
    is_auto_login_wake_input, is_command_prompt, is_continue_prompt, is_password_prompt,
    is_terminal_report_sequence, is_username_prompt, AutoLogin, AutoLoginAction,
    AutoLoginOptions,
};
pub use protocol::{
    escape_iac, normalize_nvt_newlines, EchoMode, Incoming, Negotiator, NegotiatorOutput, Parser,
    ParserEvent, TelnetCodec,
};
