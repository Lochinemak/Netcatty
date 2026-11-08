//! YMODEM batch transfers over a byte stream (serial sessions).
//!
//! Port of `electron/bridges/ymodemTransfer.cjs`: CRC-16 packets, 1 KiB
//! data blocks, a block-0 file header (`name\0size mtime mode`), the
//! EOT / NAK / EOT handshake and the empty end-of-batch header. Error codes
//! (`YMODEM_*`) are the Electron ones; the renderer shows `message`.

use crate::crc::crc16;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const SOH: u8 = 0x01;
pub const STX: u8 = 0x02;
pub const EOT: u8 = 0x04;
pub const ACK: u8 = 0x06;
pub const NAK: u8 = 0x15;
pub const CAN: u8 = 0x18;
pub const CRC16_REQUEST: u8 = b'C';
pub const BACKSPACE: u8 = 0x08;
pub const PACKET_SIZE_128: usize = 128;
pub const PACKET_SIZE_1024: usize = 1024;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_RETRY_LIMIT: usize = 10;

/// CAN ×5 then BS ×5 (sent to stop the peer).
pub const CANCEL_SEQUENCE: [u8; 10] = [
    CAN, CAN, CAN, CAN, CAN, BACKSPACE, BACKSPACE, BACKSPACE, BACKSPACE, BACKSPACE,
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct YmodemError {
    pub code: &'static str,
    pub message: String,
}

impl YmodemError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn timeout() -> Self {
        Self::new("YMODEM_TIMEOUT", "Timed out waiting for YMODEM receiver")
    }

    pub fn cancelled() -> Self {
        Self::new("YMODEM_CANCELLED", "YMODEM transfer cancelled")
    }

    pub fn closed() -> Self {
        Self::new(
            "YMODEM_SERIAL_CLOSED",
            "Serial port closed during YMODEM transfer",
        )
    }

    fn io(err: std::io::Error) -> Self {
        Self::new("YMODEM_TRANSFER_ERROR", err.to_string())
    }
}

pub type YResult<T> = Result<T, YmodemError>;

/// Byte transport of a transfer. `read_byte` fails with
/// [`YmodemError::timeout`] after `timeout`, [`YmodemError::cancelled`] on
/// cancellation and [`YmodemError::closed`] when the port went away.
pub trait YmodemIo: Send {
    fn write(&mut self, data: &[u8]) -> impl Future<Output = YResult<()>> + Send;
    fn read_byte(&mut self, timeout: Duration) -> impl Future<Output = YResult<u8>> + Send;
    /// Push a byte back to the front of the input.
    fn unread_byte(&mut self, byte: u8);
}

/// Packet: header, block number, complement, payload, CRC16 (big endian).
pub fn create_packet(header: u8, block: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 5);
    packet.push(header);
    packet.push(block);
    packet.push(0xff - block);
    packet.extend_from_slice(payload);
    packet.extend_from_slice(&crc16(payload).to_be_bytes());
    packet
}

/// Block 0: `basename\0size mtime(octal) mode(octal)`, 128 or 1024 bytes.
pub fn file_info_packet(filename: &str, size: u64, mtime: u64, mode: u32) -> Vec<u8> {
    let base = Path::new(filename)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let metadata = format!("{base}\0{size} {mtime:o} {mode:o}");
    let bytes = metadata.as_bytes();
    let size = if bytes.len() >= PACKET_SIZE_128 {
        PACKET_SIZE_1024
    } else {
        PACKET_SIZE_128
    };
    let mut payload = vec![0u8; size];
    let n = bytes.len().min(size);
    payload[..n].copy_from_slice(&bytes[..n]);
    create_packet(if size == PACKET_SIZE_1024 { STX } else { SOH }, 0, &payload)
}

/// 1 KiB data packets padded with SUB (0x1a), block numbers from 1.
pub fn data_packets(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(PACKET_SIZE_1024)
        .enumerate()
        .map(|(i, chunk)| {
            let mut payload = vec![0x1au8; PACKET_SIZE_1024];
            payload[..chunk.len()].copy_from_slice(chunk);
            create_packet(STX, ((i + 1) & 0xff) as u8, &payload)
        })
        .collect()
}

/// The empty block 0 that ends a batch.
pub fn end_session_packet() -> Vec<u8> {
    create_packet(SOH, 0, &[0u8; PACKET_SIZE_128])
}

/// Basename safe for every file system (`sanitizeYmodemFilename`).
pub fn sanitize_filename(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (c as u32) < 0x20 {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "ymodem-received.bin".to_string()
    } else {
        cleaned
    }
}

/// Parsed block-0 payload; `None` for the end-of-batch header.
pub fn parse_file_info(payload: &[u8]) -> YResult<Option<(String, u64)>> {
    let nul = payload.iter().position(|&b| b == 0);
    let raw_name = &payload[..nul.unwrap_or(payload.len())];
    if raw_name.is_empty() {
        return Ok(None);
    }
    let name = String::from_utf8_lossy(raw_name).into_owned();
    let metadata = match nul {
        Some(n) => {
            let rest = &payload[n + 1..];
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            String::from_utf8_lossy(&rest[..end]).trim().to_string()
        }
        None => String::new(),
    };
    let size_text = metadata.split_whitespace().next().unwrap_or("");
    if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(YmodemError::new(
            "YMODEM_INVALID_SIZE",
            "YMODEM file header has an invalid size",
        ));
    }
    let size = size_text.parse::<u64>().unwrap_or(0);
    Ok(Some((sanitize_filename(&name), size)))
}

/// `name`, `name (1)`, `name (2)`… — the first that does not exist.
pub fn unique_destination(dir: &Path, file_name: &str) -> YResult<PathBuf> {
    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for attempt in 0..10_000 {
        let name = if attempt == 0 {
            file_name.to_string()
        } else {
            format!("{stem} ({attempt}){ext}")
        };
        let candidate = dir.join(name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(YmodemError::new(
        "YMODEM_DESTINATION_EXISTS",
        "Could not choose a destination file name",
    ))
}

async fn read_expected<I: YmodemIo>(
    io: &mut I,
    expected: &[u8],
    timeout: Duration,
    label: &str,
) -> YResult<u8> {
    loop {
        let byte = io.read_byte(timeout).await?;
        if byte == CAN {
            match io.read_byte(Duration::from_secs(1)).await {
                Ok(CAN) => {
                    return Err(YmodemError::new(
                        "YMODEM_REMOTE_CANCELLED",
                        "YMODEM transfer cancelled by receiver",
                    ))
                }
                Ok(next) => io.unread_byte(next),
                Err(e) if e.code == "YMODEM_TIMEOUT" => {}
                Err(e) => return Err(e),
            }
            continue;
        }
        if expected.contains(&byte) {
            return Ok(byte);
        }
        if matches!(byte, CRC16_REQUEST | ACK | NAK) {
            continue;
        }
        return Err(YmodemError::new(
            "YMODEM_TRANSFER_ERROR",
            format!("Unexpected YMODEM byte while waiting for {label}: 0x{byte:x}"),
        ));
    }
}

async fn send_packet_with_retry<I: YmodemIo>(
    io: &mut I,
    packet: &[u8],
    timeout: Duration,
    retry_limit: usize,
    sent: &mut usize,
) -> YResult<()> {
    for _ in 0..retry_limit {
        io.write(packet).await?;
        *sent += 1;
        if read_expected(io, &[ACK, NAK], timeout, "packet ACK").await? == ACK {
            return Ok(());
        }
    }
    Err(YmodemError::new(
        "YMODEM_RETRY_LIMIT",
        "YMODEM receiver rejected the packet too many times",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendResult {
    pub file_name: String,
    pub total_bytes: u64,
    pub written_bytes: u64,
    pub packets_sent: usize,
}

/// Send one file (`sendYmodemBuffer`): the receiver drives with `C`.
pub async fn send_buffer<I: YmodemIo>(
    io: &mut I,
    filename: &str,
    data: &[u8],
    mtime: u64,
    timeout: Duration,
    retry_limit: usize,
) -> YResult<SendResult> {
    let header = file_info_packet(filename, data.len() as u64, mtime, 0o100644);
    let packets = data_packets(data);
    let mut sent = 0usize;

    read_expected(io, &[CRC16_REQUEST], timeout, "initial receiver request").await?;
    send_packet_with_retry(io, &header, timeout, retry_limit, &mut sent).await?;

    let mut requested = false;
    for _ in 0..retry_limit {
        let response =
            read_expected(io, &[CRC16_REQUEST, NAK], timeout, "data receiver request").await?;
        if response == CRC16_REQUEST {
            requested = true;
            break;
        }
        send_packet_with_retry(io, &header, timeout, retry_limit, &mut sent).await?;
    }
    if !requested {
        return Err(YmodemError::new(
            "YMODEM_RETRY_LIMIT",
            "YMODEM receiver did not request data after header",
        ));
    }

    for packet in &packets {
        send_packet_with_retry(io, packet, timeout, retry_limit, &mut sent).await?;
    }

    io.write(&[EOT]).await?;
    if read_expected(io, &[NAK, ACK], timeout, "first EOT response").await? == NAK {
        io.write(&[EOT]).await?;
        read_expected(io, &[ACK], timeout, "second EOT ACK").await?;
    }

    read_expected(io, &[CRC16_REQUEST], timeout, "end session request").await?;
    send_packet_with_retry(io, &end_session_packet(), timeout, retry_limit, &mut sent).await?;

    let file_name = Path::new(filename)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    Ok(SendResult {
        file_name,
        total_bytes: data.len() as u64,
        written_bytes: data.len() as u64,
        packets_sent: sent,
    })
}

/// Send a file from disk (`sendYmodemFile`).
pub async fn send_file<I: YmodemIo>(
    io: &mut I,
    path: &Path,
    timeout: Duration,
    retry_limit: usize,
) -> YResult<SendResult> {
    let meta = tokio::fs::metadata(path).await.map_err(YmodemError::io)?;
    if !meta.is_file() {
        return Err(YmodemError::new("YMODEM_NOT_FILE", "Selected path is not a file"));
    }
    let data = tokio::fs::read(path).await.map_err(YmodemError::io)?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    send_buffer(
        io,
        &path.to_string_lossy(),
        &data,
        mtime,
        timeout,
        retry_limit,
    )
    .await
}

enum Frame {
    Eot,
    Packet {
        block: u8,
        payload: Vec<u8>,
        valid: bool,
    },
}

async fn read_frame<I: YmodemIo>(io: &mut I, timeout: Duration) -> YResult<Frame> {
    loop {
        let header = io.read_byte(timeout).await?;
        if header == CAN {
            match io.read_byte(Duration::from_secs(1)).await {
                Ok(CAN) => {
                    return Err(YmodemError::new(
                        "YMODEM_REMOTE_CANCELLED",
                        "YMODEM transfer cancelled by sender",
                    ))
                }
                Ok(next) => io.unread_byte(next),
                Err(e) if e.code == "YMODEM_TIMEOUT" => {}
                Err(e) => return Err(e),
            }
            continue;
        }
        if header == EOT {
            return Ok(Frame::Eot);
        }
        if header != SOH && header != STX {
            return Err(YmodemError::new(
                "YMODEM_TRANSFER_ERROR",
                format!("Unexpected YMODEM packet header: 0x{header:x}"),
            ));
        }
        let size = if header == SOH {
            PACKET_SIZE_128
        } else {
            PACKET_SIZE_1024
        };
        let block = io.read_byte(timeout).await?;
        let complement = io.read_byte(timeout).await?;
        let mut payload = Vec::with_capacity(size);
        for _ in 0..size {
            payload.push(io.read_byte(timeout).await?);
        }
        let hi = io.read_byte(timeout).await?;
        let lo = io.read_byte(timeout).await?;
        let valid = complement == 0xff - block && u16::from_be_bytes([hi, lo]) == crc16(&payload);
        return Ok(Frame::Packet {
            block,
            payload,
            valid,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedFile {
    pub file_name: String,
    pub file_path: PathBuf,
    pub total_bytes: u64,
    pub written_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveResult {
    pub files: Vec<ReceivedFile>,
}

impl ReceiveResult {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.total_bytes).sum()
    }
    pub fn written_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.written_bytes).sum()
    }
}

async fn read_header_with_retry<I: YmodemIo>(
    io: &mut I,
    timeout: Duration,
    retry_limit: usize,
) -> YResult<Frame> {
    for attempt in 0..retry_limit {
        io.write(&[CRC16_REQUEST]).await?;
        let frame = match read_frame(io, timeout).await {
            Ok(frame) => frame,
            Err(e) if e.code == "YMODEM_TIMEOUT" && attempt + 1 < retry_limit => continue,
            Err(e) => return Err(e),
        };
        match frame {
            Frame::Eot => return Ok(Frame::Eot),
            Frame::Packet { block: 0, valid: true, .. } => return Ok(frame),
            Frame::Packet { block: 0xff, valid: true, .. } => io.write(&[ACK]).await?,
            Frame::Packet { .. } => io.write(&[NAK]).await?,
        }
    }
    Err(YmodemError::new(
        "YMODEM_RETRY_LIMIT",
        "YMODEM sender did not provide a valid file header",
    ))
}

async fn receive_file_data<I: YmodemIo>(
    io: &mut I,
    file: &mut tokio::fs::File,
    total: u64,
    timeout: Duration,
    retry_limit: usize,
) -> YResult<u64> {
    use tokio::io::AsyncWriteExt;
    let mut expected: u8 = 1;
    let mut written: u64 = 0;
    let mut rejected = 0usize;
    loop {
        let frame = match read_frame(io, timeout).await {
            Ok(frame) => frame,
            Err(e) if e.code == "YMODEM_TIMEOUT" && rejected < retry_limit => {
                rejected += 1;
                io.write(&[NAK]).await?;
                continue;
            }
            Err(e) => return Err(e),
        };
        let (block, payload, valid) = match frame {
            Frame::Eot => {
                io.write(&[NAK]).await?;
                if !matches!(read_frame(io, timeout).await?, Frame::Eot) {
                    return Err(YmodemError::new(
                        "YMODEM_EOT_EXPECTED",
                        "YMODEM sender did not confirm end of file",
                    ));
                }
                io.write(&[ACK]).await?;
                file.flush().await.map_err(YmodemError::io)?;
                if written != total {
                    return Err(YmodemError::new(
                        "YMODEM_INCOMPLETE_FILE",
                        format!("YMODEM received incomplete file ({written}/{total} bytes)"),
                    ));
                }
                return Ok(written);
            }
            Frame::Packet { block, payload, valid } => (block, payload, valid),
        };
        if !valid {
            rejected += 1;
            if rejected > retry_limit {
                return Err(YmodemError::new(
                    "YMODEM_RETRY_LIMIT",
                    "YMODEM sender sent too many invalid packets",
                ));
            }
            io.write(&[NAK]).await?;
            continue;
        }
        if block == expected.wrapping_sub(1) {
            io.write(&[ACK]).await?;
            continue;
        }
        if block != expected {
            rejected += 1;
            if rejected > retry_limit {
                return Err(YmodemError::new(
                    "YMODEM_RETRY_LIMIT",
                    "YMODEM sender sent packets out of order",
                ));
            }
            io.write(&[NAK]).await?;
            continue;
        }
        let remaining = total.saturating_sub(written);
        let n = (payload.len() as u64).min(remaining) as usize;
        if n > 0 {
            file.write_all(&payload[..n]).await.map_err(YmodemError::io)?;
            written += n as u64;
        }
        rejected = 0;
        expected = expected.wrapping_add(1);
        io.write(&[ACK]).await?;
    }
}

/// Receive a batch into `destination_dir` (`receiveYmodemFiles`). Files
/// never overwrite: `name (1).ext` etc. A failed file is removed.
pub async fn receive_files<I: YmodemIo>(
    io: &mut I,
    destination_dir: &Path,
    timeout: Duration,
    retry_limit: usize,
) -> YResult<ReceiveResult> {
    let not_dir = || {
        YmodemError::new(
            "YMODEM_DESTINATION_NOT_DIRECTORY",
            "Selected destination is not a directory",
        )
    };
    let meta = tokio::fs::metadata(destination_dir)
        .await
        .map_err(|_| not_dir())?;
    if !meta.is_dir() {
        return Err(not_dir());
    }
    let mut files = Vec::new();
    loop {
        let payload = match read_header_with_retry(io, timeout, retry_limit).await? {
            Frame::Eot => {
                io.write(&[ACK]).await?;
                continue;
            }
            Frame::Packet { payload, .. } => payload,
        };
        let info = parse_file_info(&payload)?;
        io.write(&[ACK]).await?;
        let Some((file_name, total)) = info else {
            break;
        };
        io.write(&[CRC16_REQUEST]).await?;
        let path = unique_destination(destination_dir, &file_name)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(YmodemError::io)?;
        match receive_file_data(io, &mut file, total, timeout, retry_limit).await {
            Ok(written) => {
                drop(file);
                files.push(ReceivedFile {
                    file_name: path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    file_path: path,
                    total_bytes: total,
                    written_bytes: written,
                });
            }
            Err(e) => {
                drop(file);
                let _ = tokio::fs::remove_file(&path).await;
                return Err(e);
            }
        }
    }
    Ok(ReceiveResult { files })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::sync::mpsc;

    /// One end of an in-memory serial line.
    struct Pipe {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        queue: VecDeque<u8>,
        /// Corrupt the n-th written packet (to exercise NAK / retry).
        corrupt_write: Option<usize>,
        writes: usize,
    }

    fn pipe() -> (Pipe, Pipe) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        (
            Pipe { tx: a_tx, rx: b_rx, queue: VecDeque::new(), corrupt_write: None, writes: 0 },
            Pipe { tx: b_tx, rx: a_rx, queue: VecDeque::new(), corrupt_write: None, writes: 0 },
        )
    }

    impl YmodemIo for Pipe {
        async fn write(&mut self, data: &[u8]) -> YResult<()> {
            self.writes += 1;
            let mut data = data.to_vec();
            if self.corrupt_write == Some(self.writes) && data.len() > 10 {
                data[5] ^= 0xff;
            }
            self.tx.send(data).map_err(|_| YmodemError::closed())
        }

        async fn read_byte(&mut self, timeout: Duration) -> YResult<u8> {
            loop {
                if let Some(b) = self.queue.pop_front() {
                    return Ok(b);
                }
                match tokio::time::timeout(timeout, self.rx.recv()).await {
                    Ok(Some(chunk)) => self.queue.extend(chunk),
                    Ok(None) => return Err(YmodemError::closed()),
                    Err(_) => return Err(YmodemError::timeout()),
                }
            }
        }

        fn unread_byte(&mut self, byte: u8) {
            self.queue.push_front(byte);
        }
    }

    #[test]
    fn packets_and_headers() {
        let header = file_info_packet("/tmp/dir/firmware.bin", 2048, 0o14, 0o100644);
        assert_eq!(header[0], SOH);
        assert_eq!((header[1], header[2]), (0, 0xff));
        assert_eq!(header.len(), 3 + 128 + 2);
        assert_eq!(&header[3..21], b"firmware.bin\x002048 ");
        let parsed = parse_file_info(&header[3..131]).unwrap().unwrap();
        assert_eq!(parsed, ("firmware.bin".to_string(), 2048));
        let packets = data_packets(&[1u8; 1500]);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[1][1], 2);
        assert_eq!(packets[1][3 + 476], 0x1a);
        assert_eq!(parse_file_info(&[0u8; 128]).unwrap(), None);
        assert!(parse_file_info(b"x\0abc").is_err());
        assert_eq!(sanitize_filename("..\\a:b?.txt"), "a_b_.txt");
        assert_eq!(sanitize_filename("dir/.."), "ymodem-received.bin");
        // Long names switch to a 1 KiB header block.
        let long = "n".repeat(200);
        assert_eq!(file_info_packet(&long, 1, 0, 0)[0], STX);
    }

    #[tokio::test]
    async fn send_and_receive_roundtrip_with_a_corrupted_packet() {
        let dir = std::env::temp_dir().join(format!("ymodem-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.bin"), b"existing").unwrap();
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();

        let (mut sender, mut receiver) = pipe();
        sender.corrupt_write = Some(3);
        let t = Duration::from_secs(5);
        let send_data = data.clone();
        let send = tokio::spawn(async move {
            send_buffer(&mut sender, "/x/data.bin", &send_data, 0, t, 10).await
        });
        let dir2 = dir.clone();
        let recv = tokio::spawn(async move { receive_files(&mut receiver, &dir2, t, 10).await });
        let sent = send.await.unwrap().unwrap();
        let received = recv.await.unwrap().unwrap();
        assert_eq!(sent.total_bytes, 3000);
        assert_eq!(received.files.len(), 1);
        let file = &received.files[0];
        assert_eq!(file.file_name, "data (1).bin");
        assert_eq!(std::fs::read(&file.file_path).unwrap(), data);
        assert_eq!(received.written_bytes(), 3000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn remote_cancel_is_reported() {
        let (mut a, mut b) = pipe();
        b.write(&CANCEL_SEQUENCE).await.unwrap();
        let err = send_buffer(&mut a, "f", b"x", 0, Duration::from_secs(1), 3)
            .await
            .unwrap_err();
        assert_eq!(err.code, "YMODEM_REMOTE_CANCELLED");
    }

    #[tokio::test]
    async fn receiver_timeout() {
        let (mut a, _b) = pipe();
        let err = send_buffer(&mut a, "f", b"x", 0, Duration::from_millis(20), 3)
            .await
            .unwrap_err();
        assert_eq!(err.code, "YMODEM_TIMEOUT");
    }

    #[tokio::test]
    async fn destination_must_be_a_directory() {
        let (mut a, _b) = pipe();
        let err = receive_files(&mut a, Path::new("/definitely/not/here"), Duration::from_millis(10), 1)
            .await
            .unwrap_err();
        assert_eq!(err.code, "YMODEM_DESTINATION_NOT_DIRECTORY");
    }
}
