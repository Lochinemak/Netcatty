//! `netcatty-sftp` — SFTP browsing and streaming transfers over an
//! authenticated [`netcatty_ssh::SshConnection`].
//!
//! Mirrors `electron/bridges/sftpBridge.cjs` (browse operations) and the
//! streaming subset of `transferBridge.cjs` (single-file upload/download with
//! progress, cancellation and resume from a byte checkpoint).
//!
//! Filename encoding: SFTP carries raw bytes. `SftpFilenameEncoding::Gb18030`
//! decodes/encodes names with GB18030; `Utf8` is strict UTF-8 with lossy
//! fallback; `Auto` tries UTF-8 then GB18030.

pub mod client;
pub mod error;
pub mod transfer;

pub use client::SftpClient;
pub use error::{SftpError, SftpResult};
pub use transfer::{TransferHandle, TransferProgress, TransferRequest};
