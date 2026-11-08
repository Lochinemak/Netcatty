//! ZMODEM and YMODEM for Netcatty terminal sessions.
//!
//! Port of the Electron implementation (`electron/bridges/zmodemHelper.cjs`
//! on top of `zmodem.js`, and `electron/bridges/ymodemTransfer.cjs`):
//!
//! * [`crc`], [`zdle`], [`header`], [`subpacket`]: ZMODEM framing.
//! * [`session`]: sans-IO receive (`sz` on the remote → download) and send
//!   (`rz` on the remote → upload) state machines.
//! * [`sentry`]: wraps a session's raw output, detects `rz` / `sz` start
//!   sequences, routes protocol bytes to the active session and returns the
//!   bytes that may be shown in the terminal (hex-header garble stripping,
//!   command-echo suppression, post-abort cooldown).
//! * [`ymodem`]: YMODEM batch send / receive over a byte stream (serial).
//!
//! Nothing here performs I/O except [`ymodem`]'s async drivers, which talk
//! to the transport through the [`ymodem::YmodemIo`] trait.

pub mod crc;
pub mod header;
pub mod sentry;
pub mod session;
pub mod subpacket;
pub mod ymodem;
pub mod zdle;

/// Errors of the ZMODEM state machines. Messages mirror `zmodem.js` where
/// the renderer may show them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZmodemError {
    #[error("{0}")]
    Protocol(String),
    #[error("CRC check failed")]
    Crc,
    /// The peer sent the abort sequence (5× CAN).
    #[error("peer_aborted")]
    PeerAborted,
    /// The receiver answered with `C`: it fell back to YMODEM.
    #[error("Receiver has fallen back to YMODEM.")]
    YmodemFallback,
}

impl ZmodemError {
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

pub type ZResult<T> = Result<T, ZmodemError>;

/// ZDLE / CAN.
pub const ZDLE: u8 = 0x18;
pub const XON: u8 = 0x11;
pub const XOFF: u8 = 0x13;
/// Five CANs: the ZMODEM abort sequence.
pub const ABORT_SEQUENCE: [u8; 5] = [ZDLE; 5];
/// `abort()` payload: the abort sequence followed by five backspaces.
pub const ABORT_WITH_BACKSPACES: [u8; 10] = [
    ZDLE, ZDLE, ZDLE, ZDLE, ZDLE, 0x08, 0x08, 0x08, 0x08, 0x08,
];
/// Extra CANs Netcatty sends after an abort so a streaming `sz` stops.
pub const EXTRA_ABORT_BYTES: [u8; 8] = [ZDLE; 8];
