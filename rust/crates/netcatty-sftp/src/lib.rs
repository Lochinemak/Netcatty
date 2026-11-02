//! `netcatty-sftp` — SFTP browsing and streaming transfers over an
//! authenticated [`netcatty_ssh::SshConnection`].
//!
//! Mirrors `electron/bridges/sftpBridge.cjs` (browse operations) and the
//! streaming subset of `transferBridge.cjs` (single-file upload/download with
//! progress, cancellation and resume from a byte checkpoint).
//!
//! Filename encoding: SFTP carries raw bytes. `SftpFilenameEncoding::Gb18030`
//! decodes/encodes names with GB18030; `Utf8` is strict UTF-8 with lossy
//! fallback; `Auto` tries UTF-8 then GB18030 (and, like the Electron bridge,
//! switches a session to GB18030 for outgoing paths once a listing contains
//! non-UTF-8 names). Raw bytes survive `russh-sftp`'s `String` API thanks to
//! the byte-preserving transport in [`wire`].

pub mod client;
pub mod error;
mod pipeline;
pub mod transfer;
pub mod wire;

pub use client::{
    archive_kind, build_extract_command, decode_name, encode_path, posix_basename, posix_parent,
    shell_quote, shell_quote_bytes, ArchiveKind, SftpClient, TransferLimits,
};
pub use error::{SftpError, SftpResult};
pub use transfer::{
    remote_staging_path, staging_path, start_transfer, start_transfer_with, SpeedCalculator,
    TransferEndpoints, TransferHandle, TransferOutcome, TransferProgress, TransferRequest,
    TransferTuning,
};
