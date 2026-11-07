//! Serial port sessions.
//!
//! Port of the serial parts of `electron/bridges/terminalBridge.cjs` and
//! `serialNamedPipe.cjs`:
//!
//! * [`list_ports`] — hardware ports (`listSerialPorts`), same shape as the
//!   Node `serialport` listing.
//! * [`SerialSession::open`] — opens a hardware port or PTY device with the
//!   requested line settings (or, on Windows, a local `\\.\pipe\...` named
//!   pipe such as a Hyper-V VM console) and streams its bytes.
//! * [`expand_backspace`] — the byte-oriented erase handling of
//!   `expandSerialBackspace`.
//!
//! The `serialport` crate is used without its `libudev` feature: on Linux
//! ports are enumerated from sysfs, so no system library is needed.

use bytes::Bytes;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Reader poll interval: how quickly a closed session's reader notices.
#[cfg_attr(not(unix), allow(dead_code))]
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
const READ_CHUNK: usize = 16 * 1024;
const EVENT_CHANNEL_CAPACITY: usize = 1024;
const WRITE_CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum SerialError {
    #[error("{0}")]
    InvalidArgument(String),
    /// Opening failed; the message is the platform error.
    #[error("{0}")]
    Open(String),
    #[error("serial port is closed")]
    Closed,
}

impl From<SerialError> for netcatty_core::CoreError {
    fn from(err: SerialError) -> Self {
        match err {
            SerialError::InvalidArgument(m) => netcatty_core::CoreError::invalid(m),
            SerialError::Open(m) => netcatty_core::CoreError::io(m),
            SerialError::Closed => netcatty_core::CoreError::not_found("serial port is closed"),
        }
    }
}

/// One entry of `listSerialPorts()` (Node `serialport` listing shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SerialPortListing {
    pub path: String,
    pub manufacturer: String,
    pub serial_number: String,
    pub vendor_id: String,
    pub product_id: String,
    pub pnp_id: String,
    /// Always `"hardware"` (PTY devices can be opened but are not listed).
    #[serde(rename = "type")]
    pub kind: &'static str,
}

/// Hardware serial ports. Errors are logged and yield an empty list, like
/// the Electron bridge.
pub fn list_ports() -> Vec<SerialPortListing> {
    match serialport::available_ports() {
        Ok(ports) => ports.into_iter().map(listing_of).collect(),
        Err(err) => {
            tracing::warn!(%err, "failed to list serial ports");
            Vec::new()
        }
    }
}

fn listing_of(port: serialport::SerialPortInfo) -> SerialPortListing {
    let mut listing = SerialPortListing {
        path: port.port_name,
        manufacturer: String::new(),
        serial_number: String::new(),
        vendor_id: String::new(),
        product_id: String::new(),
        pnp_id: String::new(),
        kind: "hardware",
    };
    if let serialport::SerialPortType::UsbPort(usb) = port.port_type {
        listing.manufacturer = usb.manufacturer.unwrap_or_default();
        listing.serial_number = usb.serial_number.unwrap_or_default();
        listing.vendor_id = format!("{:04x}", usb.vid);
        listing.product_id = format!("{:04x}", usb.pid);
    }
    listing
}

/// Local Windows IPC only: `\\.\pipe\name` or `\\?\pipe\name`. Remote UNC
/// paths are not treated as serial ports. Mirrors `isWindowsNamedPipePath`
/// (and `domain/serialEndpoint.ts`).
pub fn is_windows_named_pipe_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let rest = lower
        .strip_prefix(r"\\.\pipe\")
        .or_else(|| lower.strip_prefix(r"\\?\pipe\"));
    match rest {
        Some(name) => !name.is_empty() && !name.contains(['\r', '\n', '\0']),
        None => false,
    }
}

/// Line settings (`startSerialSession` options; Electron defaults applied by
/// [`SerialOptions::with_defaults`]).
#[derive(Debug, Clone, PartialEq)]
pub struct SerialOptions {
    pub path: String,
    pub baud_rate: u32,
    pub data_bits: u8,
    pub stop_bits: f32,
    /// `none` | `even` | `odd` | `mark` | `space`.
    pub parity: String,
    /// `none` | `xon/xoff` | `rts/cts`.
    pub flow_control: String,
}

impl SerialOptions {
    /// Electron defaults: 115200 8N1, no flow control.
    pub fn with_defaults(
        path: &str,
        baud_rate: Option<u32>,
        data_bits: Option<u8>,
        stop_bits: Option<f32>,
        parity: Option<&str>,
        flow_control: Option<&str>,
    ) -> Self {
        Self {
            path: path.trim().to_string(),
            baud_rate: baud_rate.filter(|b| *b > 0).unwrap_or(115_200),
            data_bits: data_bits.filter(|b| *b > 0).unwrap_or(8),
            stop_bits: stop_bits.filter(|b| *b > 0.0).unwrap_or(1.0),
            parity: parity
                .filter(|p| !p.is_empty())
                .unwrap_or("none")
                .to_string(),
            flow_control: flow_control
                .filter(|f| !f.is_empty())
                .unwrap_or("none")
                .to_string(),
        }
    }
}

/// Validated `serialport` settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSettings {
    pub baud_rate: u32,
    pub data_bits: serialport::DataBits,
    pub stop_bits: serialport::StopBits,
    pub parity: serialport::Parity,
    pub flow_control: serialport::FlowControl,
}

/// Map renderer settings onto `serialport` types. 1.5 stop bits are opened
/// as 2 (the POSIX termios interface has no 1.5 setting either); mark /
/// space parity are not supported by the `serialport` crate.
pub fn line_settings(options: &SerialOptions) -> Result<LineSettings, SerialError> {
    use serialport::{DataBits, FlowControl, Parity, StopBits};
    let data_bits = match options.data_bits {
        5 => DataBits::Five,
        6 => DataBits::Six,
        7 => DataBits::Seven,
        8 => DataBits::Eight,
        other => {
            return Err(SerialError::InvalidArgument(format!(
                "unsupported data bits: {other}"
            )))
        }
    };
    let stop_bits = if options.stop_bits >= 1.5 {
        StopBits::Two
    } else {
        StopBits::One
    };
    let parity = match options.parity.to_ascii_lowercase().as_str() {
        "none" => Parity::None,
        "even" => Parity::Even,
        "odd" => Parity::Odd,
        other => {
            return Err(SerialError::InvalidArgument(format!(
                "unsupported parity: {other}"
            )))
        }
    };
    let flow_control = match options.flow_control.to_ascii_lowercase().as_str() {
        "rts/cts" => FlowControl::Hardware,
        "xon/xoff" => FlowControl::Software,
        _ => FlowControl::None,
    };
    Ok(LineSettings {
        baud_rate: options.baud_rate,
        data_bits,
        stop_bits,
        parity,
        flow_control,
    })
}

/// Output of an open serial session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialEvent {
    Data(Bytes),
    /// The port closed (EOF / hang-up) — Electron's `close` event.
    Closed,
    /// A read error ended the session — Electron's `error` event.
    Error(String),
}

/// An open serial port (or named pipe). Output arrives on `events`.
pub struct SerialSession {
    pub events: mpsc::Receiver<SerialEvent>,
    write_tx: mpsc::Sender<Bytes>,
    closed: Arc<AtomicBool>,
    pub path: String,
}

impl std::fmt::Debug for SerialSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerialSession")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SerialSession {
    /// Open the port. Errors carry the platform message; the caller prefixes
    /// `Failed to open serial port: `.
    pub async fn open(options: SerialOptions) -> Result<SerialSession, SerialError> {
        if options.path.is_empty() {
            return Err(SerialError::InvalidArgument(
                "serial port path is required".into(),
            ));
        }
        if is_windows_named_pipe_path(&options.path) {
            return open_named_pipe(options.path).await;
        }
        let settings = line_settings(&options)?;
        open_port(options.path, settings).await
    }

    pub async fn write(&self, data: Bytes) -> Result<(), SerialError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SerialError::Closed);
        }
        self.write_tx
            .send(data)
            .await
            .map_err(|_| SerialError::Closed)
    }

    /// Non-blocking write for callers outside an async context (queued
    /// behind earlier writes).
    pub fn try_write(&self, data: Bytes) -> Result<(), SerialError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SerialError::Closed);
        }
        self.write_tx
            .try_send(data)
            .map_err(|_| SerialError::Closed)
    }

    /// Close the port; no further events are delivered.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl Drop for SerialSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(any(unix, windows))]
async fn open_port(path: String, settings: LineSettings) -> Result<SerialSession, SerialError> {
    let open_path = path.clone();
    let port = tokio::task::spawn_blocking(move || {
        let open = |baud_rate: u32| {
            serialport::new(open_path.as_str(), baud_rate)
                .data_bits(settings.data_bits)
                .stop_bits(settings.stop_bits)
                .parity(settings.parity)
                .flow_control(settings.flow_control)
                .timeout(READ_TIMEOUT)
                .open()
        };
        match open(settings.baud_rate) {
            // macOS sets the speed with the IOSSIOSPEED ioctl, which pseudo
            // terminals reject with ENOTTY. Node `serialport` opens PTYs, so
            // retry without a speed (baud 0 skips that ioctl).
            Err(err) if cfg!(target_os = "macos") && is_enotty(&err) => open(0),
            other => other,
        }
    })
    .await
    .map_err(|err| SerialError::Open(err.to_string()))?
    .map_err(|err| SerialError::Open(err.to_string()))?;
    let reader = port
        .try_clone()
        .map_err(|err| SerialError::Open(err.to_string()))?;

    let closed = Arc::new(AtomicBool::new(false));
    let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (write_tx, write_rx) = mpsc::channel::<Bytes>(WRITE_CHANNEL_CAPACITY);
    spawn_reader(reader, events_tx, closed.clone())?;
    spawn_writer(port, write_rx, closed.clone())?;
    Ok(SerialSession {
        events: events_rx,
        write_tx,
        closed,
        path,
    })
}

#[cfg(any(unix, windows))]
fn is_enotty(err: &serialport::Error) -> bool {
    err.description.contains("Not a typewriter") || err.description.contains("Inappropriate ioctl")
}

#[cfg(not(any(unix, windows)))]
async fn open_port(_path: String, _settings: LineSettings) -> Result<SerialSession, SerialError> {
    Err(SerialError::Open(
        "serial ports are not supported on this platform".into(),
    ))
}

fn spawn_reader(
    mut port: Box<dyn serialport::SerialPort>,
    events_tx: mpsc::Sender<SerialEvent>,
    closed: Arc<AtomicBool>,
) -> Result<(), SerialError> {
    std::thread::Builder::new()
        .name("netcatty-serial-reader".into())
        .spawn(move || {
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                if closed.load(Ordering::SeqCst) {
                    return;
                }
                match port.read(&mut buf) {
                    Ok(0) => {
                        if !closed.load(Ordering::SeqCst) {
                            let _ = events_tx.blocking_send(SerialEvent::Closed);
                        }
                        return;
                    }
                    Ok(n) => {
                        let chunk = Bytes::copy_from_slice(&buf[..n]);
                        if events_tx.blocking_send(SerialEvent::Data(chunk)).is_err() {
                            return;
                        }
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        continue
                    }
                    Err(err) => {
                        if !closed.load(Ordering::SeqCst) {
                            let _ = events_tx.blocking_send(SerialEvent::Error(err.to_string()));
                        }
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|err| SerialError::Open(format!("failed to start serial reader: {err}")))
}

fn spawn_writer(
    mut port: Box<dyn serialport::SerialPort>,
    mut write_rx: mpsc::Receiver<Bytes>,
    closed: Arc<AtomicBool>,
) -> Result<(), SerialError> {
    std::thread::Builder::new()
        .name("netcatty-serial-writer".into())
        .spawn(move || {
            while let Some(data) = write_rx.blocking_recv() {
                if closed.load(Ordering::SeqCst) {
                    break;
                }
                let mut offset = 0;
                while offset < data.len() {
                    if closed.load(Ordering::SeqCst) {
                        return;
                    }
                    match port.write(&data[offset..]) {
                        Ok(0) => return,
                        Ok(n) => offset += n,
                        Err(err)
                            if matches!(
                                err.kind(),
                                std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::Interrupted
                                    | std::io::ErrorKind::WouldBlock
                            ) =>
                        {
                            continue
                        }
                        Err(err) => {
                            tracing::debug!(%err, "serial write failed; stopping writer");
                            return;
                        }
                    }
                }
                let _ = port.flush();
            }
            // Dropping the last handle closes the port.
        })
        .map(|_| ())
        .map_err(|err| SerialError::Open(format!("failed to start serial writer: {err}")))
}

#[cfg(windows)]
async fn open_named_pipe(path: String) -> Result<SerialSession, SerialError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    let client = ClientOptions::new()
        .open(&path)
        .map_err(|err| SerialError::Open(err.to_string()))?;
    let (mut reader, mut writer) = tokio::io::split(client);
    let closed = Arc::new(AtomicBool::new(false));
    let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(WRITE_CHANNEL_CAPACITY);

    let reader_closed = closed.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            let read = tokio::select! {
                r = reader.read(&mut buf) => r,
                _ = wait_closed(&reader_closed) => return,
            };
            match read {
                Ok(0) => {
                    if !reader_closed.load(Ordering::SeqCst) {
                        let _ = events_tx.send(SerialEvent::Closed).await;
                    }
                    return;
                }
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(&buf[..n]);
                    if events_tx.send(SerialEvent::Data(chunk)).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    if !reader_closed.load(Ordering::SeqCst) {
                        let _ = events_tx.send(SerialEvent::Error(err.to_string())).await;
                    }
                    return;
                }
            }
        }
    });
    let writer_closed = closed.clone();
    tokio::spawn(async move {
        while let Some(data) = write_rx.recv().await {
            if writer_closed.load(Ordering::SeqCst) {
                break;
            }
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    Ok(SerialSession {
        events: events_rx,
        write_tx,
        closed,
        path,
    })
}

#[cfg(windows)]
async fn wait_closed(closed: &AtomicBool) {
    while !closed.load(Ordering::SeqCst) {
        tokio::time::sleep(READ_TIMEOUT).await;
    }
}

#[cfg(not(windows))]
async fn open_named_pipe(_path: String) -> Result<SerialSession, SerialError> {
    Err(SerialError::Open(
        "Windows named pipes are only supported on Windows".into(),
    ))
}

/// Expand a single Backspace / DEL keystroke into one per encoded byte of
/// `erase_char` (byte-oriented serial devices erase byte by byte). Any other
/// input is returned unchanged. `encoded_len` gives the byte length of a
/// string in the session charset.
pub fn expand_backspace(
    data: &str,
    erase_char: Option<&str>,
    encoded_len: impl Fn(&str) -> usize,
) -> String {
    if data != "\x7f" && data != "\x08" {
        return data.to_string();
    }
    match erase_char {
        Some(ch) if !ch.is_empty() => data.repeat(encoded_len(ch).max(1)),
        _ => data.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_pipe_paths() {
        // Ported from serialNamedPipe.test.cjs.
        assert!(is_windows_named_pipe_path(r"\\.\pipe\vm-console"));
        assert!(is_windows_named_pipe_path(r"\\?\pipe\com_1"));
        assert!(is_windows_named_pipe_path(r"\\.\PIPE\Mixed"));
        assert!(!is_windows_named_pipe_path(r"\\server\pipe\remote"));
        assert!(!is_windows_named_pipe_path(r"\\.\pipe\"));
        assert!(!is_windows_named_pipe_path("\\\\.\\pipe\\bad\nname"));
        assert!(!is_windows_named_pipe_path("COM3"));
        assert!(!is_windows_named_pipe_path("/dev/ttyUSB0"));
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn named_pipes_are_windows_only() {
        let err = SerialSession::open(SerialOptions::with_defaults(
            r"\\.\pipe\vm",
            None,
            None,
            None,
            None,
            None,
        ))
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Windows named pipes are only supported on Windows"
        );
    }

    #[test]
    fn defaults_and_line_settings() {
        let o = SerialOptions::with_defaults(" /dev/ttyUSB0 ", None, None, None, None, None);
        assert_eq!(o.path, "/dev/ttyUSB0");
        assert_eq!(o.baud_rate, 115_200);
        let s = line_settings(&o).unwrap();
        assert_eq!(s.data_bits, serialport::DataBits::Eight);
        assert_eq!(s.stop_bits, serialport::StopBits::One);
        assert_eq!(s.parity, serialport::Parity::None);
        assert_eq!(s.flow_control, serialport::FlowControl::None);

        let o = SerialOptions::with_defaults(
            "COM3",
            Some(9600),
            Some(7),
            Some(2.0),
            Some("even"),
            Some("rts/cts"),
        );
        let s = line_settings(&o).unwrap();
        assert_eq!(s.baud_rate, 9600);
        assert_eq!(s.data_bits, serialport::DataBits::Seven);
        assert_eq!(s.stop_bits, serialport::StopBits::Two);
        assert_eq!(s.parity, serialport::Parity::Even);
        assert_eq!(s.flow_control, serialport::FlowControl::Hardware);

        let o = SerialOptions::with_defaults("x", None, None, Some(1.5), None, Some("xon/xoff"));
        let s = line_settings(&o).unwrap();
        assert_eq!(s.stop_bits, serialport::StopBits::Two);
        assert_eq!(s.flow_control, serialport::FlowControl::Software);

        let o = SerialOptions::with_defaults("x", None, Some(9), None, None, None);
        assert!(line_settings(&o).is_err());
        let o = SerialOptions::with_defaults("x", None, None, None, Some("mark"), None);
        assert!(line_settings(&o).is_err());
    }

    #[test]
    fn backspace_expansion() {
        // Ported from terminalBridge.serialBackspace.test.cjs: one Backspace
        // per encoded byte of the erase character.
        let utf8_len = |s: &str| s.len();
        assert_eq!(
            expand_backspace("\x7f", Some("中"), utf8_len),
            "\x7f\x7f\x7f"
        );
        assert_eq!(expand_backspace("\x08", Some("中"), |_| 2), "\x08\x08");
        assert_eq!(expand_backspace("\x7f", Some("a"), utf8_len), "\x7f");
        assert_eq!(expand_backspace("\x7f", None, utf8_len), "\x7f");
        assert_eq!(expand_backspace("\x7f", Some(""), utf8_len), "\x7f");
        assert_eq!(
            expand_backspace("\x7f\x7f", Some("中"), utf8_len),
            "\x7f\x7f"
        );
        assert_eq!(expand_backspace("x", Some("中"), utf8_len), "x");
    }

    #[test]
    fn listing_serializes_like_node_serialport() {
        let listing = listing_of(serialport::SerialPortInfo {
            port_name: "/dev/ttyUSB0".into(),
            port_type: serialport::SerialPortType::UsbPort(serialport::UsbPortInfo {
                vid: 0x0403,
                pid: 0x6001,
                serial_number: Some("A1".into()),
                manufacturer: Some("FTDI".into()),
                product: None,
            }),
        });
        let v = serde_json::to_value(&listing).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "path": "/dev/ttyUSB0",
                "manufacturer": "FTDI",
                "serialNumber": "A1",
                "vendorId": "0403",
                "productId": "6001",
                "pnpId": "",
                "type": "hardware",
            })
        );
        // Listing never panics (may be empty on CI machines).
        let _ = list_ports();
    }

    /// Round trip through a pseudo-terminal pair: the slave is opened by
    /// path like a USB adapter would be.
    #[cfg(unix)]
    #[tokio::test]
    async fn pty_round_trip() {
        use serialport::SerialPort;
        use std::io::{Read, Write};
        let (mut master, slave) = serialport::TTYPort::pair().expect("pty pair");
        let path = slave.name().expect("slave name");
        drop(slave);
        let mut session = SerialSession::open(SerialOptions::with_defaults(
            &path,
            Some(9600),
            None,
            None,
            None,
            None,
        ))
        .await
        .expect("open pty as serial port");

        session.write(Bytes::from_static(b"AT\r")).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        master
            .set_timeout(std::time::Duration::from_millis(200))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while got.len() < 3 && std::time::Instant::now() < deadline {
            if let Ok(n) = master.read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
        }
        assert_eq!(got, b"AT\r");

        master.write_all(b"OK\r\n").unwrap();
        let mut out = Vec::new();
        while out.len() < 4 {
            match tokio::time::timeout(std::time::Duration::from_secs(5), session.events.recv())
                .await
            {
                Ok(Some(SerialEvent::Data(b))) => out.extend_from_slice(&b),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(out, b"OK\r\n");
        session.close();
        assert!(session.write(Bytes::from_static(b"x")).await.is_err());
    }
}
