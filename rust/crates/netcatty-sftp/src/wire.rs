//! Byte-preserving transport layer under `russh-sftp`.
//!
//! SFTP carries filenames and handles as raw byte strings, but `russh-sftp`
//! decodes every wire `string` with `String::from_utf8_lossy` and serializes
//! `String` fields as UTF-8. A GB18030 filename would therefore be mangled
//! into U+FFFD before our code ever sees it, and could never be sent back.
//!
//! This module sits *between* the SSH channel and `russh-sftp` and rewrites
//! the path/handle fields of every packet with a lossless mapping:
//!
//! * inbound (server → client): each raw byte `b` becomes the char `U+00bb`
//!   (ISO-8859-1), so `russh-sftp` receives valid UTF-8 whose chars are the
//!   original bytes ([`to_wire`] / [`from_wire`]);
//! * outbound (client → server): the UTF-8 of such a Latin-1 string is turned
//!   back into the original bytes.
//!
//! The client layer ([`crate::client`]) therefore works on *byte strings*
//! disguised as `String`, and applies the real filename encoding
//! (`utf-8` / `gb18030` / auto-detect) itself, per call.
//!
//! As a side effect, SFTP handles that are not valid UTF-8 (some servers use
//! arbitrary bytes) survive the round trip too, and `extended` attribute
//! pairs — which `russh-sftp` cannot parse — are stripped from `SSH_FXP_NAME`
//! replies so the rest of the packet decodes correctly.
//!
//! The rewrite runs as two pump tasks around a [`tokio::io::duplex`] rather
//! than as a passive `AsyncWrite` wrapper: `russh-sftp` never flushes its
//! writer and the SSH channel writer does partial writes, so a passive
//! wrapper could leave the tail of a frame stranded with nobody to drive it.

use bytes::{BufMut, BytesMut};
use std::borrow::Cow;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

/// Upper bound for one SFTP frame (`russh-sftp` itself caps inbound packets
/// at 256 KiB; this only guards against a corrupt length prefix).
const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;
/// Buffer of each direction of the internal duplex.
const DUPLEX_BUF: usize = 1024 * 1024;

const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_NAME: u8 = 104;

const ATTR_SIZE: u32 = 0x0000_0001;
const ATTR_UIDGID: u32 = 0x0000_0002;
const ATTR_PERMISSIONS: u32 = 0x0000_0004;
const ATTR_ACMODTIME: u32 = 0x0000_0008;
const ATTR_EXTENDED: u32 = 0x8000_0000;

/// Lossless byte string → `String` mapping (every byte becomes `U+00xx`).
pub fn to_wire(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Inverse of [`to_wire`]. Chars above `U+00FF` (which never come from
/// [`to_wire`]) are emitted as their UTF-8 bytes so nothing is lost.
pub fn from_wire(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut scratch = [0u8; 4];
    for c in s.chars() {
        let cp = c as u32;
        if cp <= 0xFF {
            out.push(cp as u8);
        } else {
            out.extend_from_slice(c.encode_utf8(&mut scratch).as_bytes());
        }
    }
    out
}

/// UTF-8 bytes of the Latin-1 representation of `bytes` (what the inbound
/// pump writes in place of a raw wire string).
fn latin1_utf8(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 4);
    for &b in bytes {
        if b < 0x80 {
            out.push(b);
        } else {
            out.push(0xC0 | (b >> 6));
            out.push(0x80 | (b & 0x3F));
        }
    }
    out
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Some(out)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.put_u32(bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Number of leading `string` fields (after the request id) that carry a
/// path or handle in a client → server packet.
fn outbound_string_fields(packet_type: u8) -> usize {
    match packet_type {
        SSH_FXP_OPEN | SSH_FXP_CLOSE | SSH_FXP_READ | SSH_FXP_WRITE | SSH_FXP_LSTAT
        | SSH_FXP_FSTAT | SSH_FXP_SETSTAT | SSH_FXP_FSETSTAT | SSH_FXP_OPENDIR
        | SSH_FXP_READDIR | SSH_FXP_REMOVE | SSH_FXP_MKDIR | SSH_FXP_RMDIR | SSH_FXP_REALPATH
        | SSH_FXP_STAT | SSH_FXP_READLINK => 1,
        SSH_FXP_RENAME | SSH_FXP_SYMLINK => 2,
        _ => 0,
    }
}

/// Rewrite one client → server frame body (type byte + payload).
pub(crate) fn transform_outbound(frame: &[u8]) -> Cow<'_, [u8]> {
    fn inner(frame: &[u8], fields: usize) -> Option<Vec<u8>> {
        let mut c = Cursor::new(&frame[1..]);
        let id = c.u32()?;
        let mut out = Vec::with_capacity(frame.len());
        out.push(frame[0]);
        out.put_u32(id);
        for _ in 0..fields {
            let s = c.string()?;
            match std::str::from_utf8(s) {
                Ok(text) => put_string(&mut out, &from_wire(text)),
                // Not produced by us; leave it alone.
                Err(_) => put_string(&mut out, s),
            }
        }
        out.extend_from_slice(c.rest());
        Some(out)
    }
    let Some(&packet_type) = frame.first() else {
        return Cow::Borrowed(frame);
    };
    let fields = outbound_string_fields(packet_type);
    if fields == 0 {
        return Cow::Borrowed(frame);
    }
    match inner(frame, fields) {
        Some(v) => Cow::Owned(v),
        None => Cow::Borrowed(frame),
    }
}

/// Copy a v3 `ATTRS` structure from `c` into `out`, dropping the extended
/// pairs (and the EXTENDED flag) that `russh-sftp` cannot decode.
fn copy_attrs_without_extended(c: &mut Cursor<'_>, out: &mut Vec<u8>) -> Option<()> {
    let flags = c.u32()?;
    out.put_u32(flags & !ATTR_EXTENDED);
    if flags & ATTR_SIZE != 0 {
        out.extend_from_slice(c.take(8)?);
    }
    if flags & ATTR_UIDGID != 0 {
        out.extend_from_slice(c.take(8)?);
    }
    if flags & ATTR_PERMISSIONS != 0 {
        out.extend_from_slice(c.take(4)?);
    }
    if flags & ATTR_ACMODTIME != 0 {
        out.extend_from_slice(c.take(8)?);
    }
    if flags & ATTR_EXTENDED != 0 {
        let count = c.u32()?;
        for _ in 0..count {
            c.string()?;
            c.string()?;
        }
    }
    Some(())
}

/// Rewrite one server → client frame body (type byte + payload).
pub(crate) fn transform_inbound(frame: &[u8]) -> Cow<'_, [u8]> {
    fn handle(frame: &[u8]) -> Option<Vec<u8>> {
        let mut c = Cursor::new(&frame[1..]);
        let id = c.u32()?;
        let h = c.string()?;
        let mut out = Vec::with_capacity(frame.len() + 16);
        out.push(frame[0]);
        out.put_u32(id);
        put_string(&mut out, &latin1_utf8(h));
        out.extend_from_slice(c.rest());
        Some(out)
    }
    fn name(frame: &[u8]) -> Option<Vec<u8>> {
        let mut c = Cursor::new(&frame[1..]);
        let id = c.u32()?;
        let count = c.u32()?;
        let mut out = Vec::with_capacity(frame.len() + frame.len() / 4);
        out.push(frame[0]);
        out.put_u32(id);
        out.put_u32(count);
        for _ in 0..count {
            let filename = c.string()?;
            let longname = c.string()?;
            put_string(&mut out, &latin1_utf8(filename));
            put_string(&mut out, &latin1_utf8(longname));
            copy_attrs_without_extended(&mut c, &mut out)?;
        }
        out.extend_from_slice(c.rest());
        Some(out)
    }
    let result = match frame.first() {
        Some(&SSH_FXP_HANDLE) => handle(frame),
        Some(&SSH_FXP_NAME) => name(frame),
        _ => None,
    };
    match result {
        Some(v) => Cow::Owned(v),
        None => Cow::Borrowed(frame),
    }
}

/// Copy length-prefixed SFTP frames from `rd` to `wr`, rewriting each body
/// with `transform`. Ends at EOF of `rd` (a trailing partial frame is
/// dropped) or on the first I/O error.
async fn pump<R, W>(mut rd: R, mut wr: W, transform: fn(&[u8]) -> Cow<'_, [u8]>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(64 * 1024);
    loop {
        // Wait for a complete frame.
        loop {
            if buf.len() >= 4 {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if len > MAX_FRAME_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sftp frame too large",
                    ));
                }
                if buf.len() >= 4 + len {
                    break;
                }
                buf.reserve(4 + len - buf.len());
            }
            let n = rd.read_buf(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let frame = buf.split_to(4 + len);
        let body = &frame[4..];
        let out = transform(body);
        let header = (out.len() as u32).to_be_bytes();
        wr.write_all(&header).await?;
        wr.write_all(&out).await?;
        // `flush` is a no-op on both the duplex and the channel stream but
        // keeps the contract honest for other transports.
        wr.flush().await?;
    }
}

/// Wrap the SFTP subsystem channel stream. The returned stream speaks SFTP
/// with byte-preserving (`Latin-1`-mapped) path and handle strings; hand it
/// to `RawSftpSession::new_with_config`.
pub fn wrap<S>(stream: S) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(DUPLEX_BUF);
    let (chan_rd, chan_wr) = tokio::io::split(stream);
    let (app_rd, app_wr) = tokio::io::split(ours);

    // server → russh-sftp
    tokio::spawn(async move {
        let mut app_wr = app_wr;
        if let Err(err) = pump(chan_rd, &mut app_wr, transform_inbound).await {
            tracing::debug!(error = %err, "sftp inbound pump ended");
        }
        let _ = app_wr.shutdown().await;
    });

    // russh-sftp → server
    tokio::spawn(async move {
        let mut chan_wr = chan_wr;
        if let Err(err) = pump(app_rd, &mut chan_wr, transform_outbound).await {
            tracing::debug!(error = %err, "sftp outbound pump ended");
        }
        let _ = chan_wr.shutdown().await;
    });

    theirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn wire_round_trip_is_lossless() {
        let raw: Vec<u8> = (0u8..=255).collect();
        assert_eq!(from_wire(&to_wire(&raw)), raw);
        assert_eq!(to_wire(b"abc"), "abc");
        // Chars beyond Latin-1 degrade to their UTF-8 bytes.
        assert_eq!(from_wire("中"), "中".as_bytes());
    }

    #[test]
    fn outbound_rewrites_path_fields_only() {
        // SSH_FXP_RENAME id=7 oldpath newpath + trailing junk
        let old = to_wire(b"\xd6\xd0");
        let new = to_wire(b"x\xff");
        let mut body = vec![SSH_FXP_RENAME, 0, 0, 0, 7];
        put_string(&mut body, old.as_bytes());
        put_string(&mut body, new.as_bytes());
        body.extend_from_slice(&[9, 9]);
        let out = transform_outbound(&body);
        let mut expected = vec![SSH_FXP_RENAME, 0, 0, 0, 7];
        put_string(&mut expected, b"\xd6\xd0");
        put_string(&mut expected, b"x\xff");
        expected.extend_from_slice(&[9, 9]);
        assert_eq!(out.as_ref(), expected.as_slice());

        // WRITE: handle rewritten, offset + data untouched.
        let mut body = vec![SSH_FXP_WRITE, 0, 0, 0, 1];
        put_string(&mut body, to_wire(b"\x00\x80").as_bytes());
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        put_string(&mut body, b"\xc3\xa9data");
        let out = transform_outbound(&body);
        let mut expected = vec![SSH_FXP_WRITE, 0, 0, 0, 1];
        put_string(&mut expected, b"\x00\x80");
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        put_string(&mut expected, b"\xc3\xa9data");
        assert_eq!(out.as_ref(), expected.as_slice());

        // Unrelated packet types pass through untouched.
        let init = [1u8, 0, 0, 0, 3];
        assert!(matches!(transform_outbound(&init), Cow::Borrowed(_)));
    }

    #[test]
    fn inbound_rewrites_handle_and_name_and_strips_extended_attrs() {
        let mut body = vec![SSH_FXP_HANDLE, 0, 0, 0, 2];
        put_string(&mut body, b"\xfe\x01");
        let out = transform_inbound(&body);
        let mut expected = vec![SSH_FXP_HANDLE, 0, 0, 0, 2];
        put_string(&mut expected, to_wire(b"\xfe\x01").as_bytes());
        assert_eq!(out.as_ref(), expected.as_slice());

        // NAME with one entry carrying size + extended attrs.
        let mut body = vec![SSH_FXP_NAME, 0, 0, 0, 3, 0, 0, 0, 1];
        put_string(&mut body, b"\xd6\xd0\xce\xc4");
        put_string(
            &mut body,
            b"-rw-r--r-- 1 u g 4 Jan 1 00:00 \xd6\xd0\xce\xc4",
        );
        body.put_u32(ATTR_SIZE | ATTR_EXTENDED);
        body.put_u64(4);
        body.put_u32(1);
        put_string(&mut body, b"ext@x");
        put_string(&mut body, b"data");
        let out = transform_inbound(&body);
        let mut expected = vec![SSH_FXP_NAME, 0, 0, 0, 3, 0, 0, 0, 1];
        put_string(&mut expected, to_wire(b"\xd6\xd0\xce\xc4").as_bytes());
        put_string(
            &mut expected,
            to_wire(b"-rw-r--r-- 1 u g 4 Jan 1 00:00 \xd6\xd0\xce\xc4").as_bytes(),
        );
        expected.put_u32(ATTR_SIZE);
        expected.put_u64(4);
        assert_eq!(out.as_ref(), expected.as_slice());

        // Truncated packets are left alone rather than corrupted.
        let bad = [SSH_FXP_NAME, 0, 0, 0, 3, 0, 0, 0, 9];
        assert!(matches!(transform_inbound(&bad), Cow::Borrowed(_)));
    }

    #[tokio::test]
    async fn pumps_reframe_across_split_chunks() {
        let (server_side, our_side) = tokio::io::duplex(64);
        let app = wrap(our_side);
        let (mut srv_rd, mut srv_wr) = tokio::io::split(server_side);
        let (mut app_rd, mut app_wr) = tokio::io::split(app);

        // Server sends a HANDLE reply in two pieces.
        let mut body = vec![SSH_FXP_HANDLE, 0, 0, 0, 1];
        put_string(&mut body, b"\xff\x00");
        let bytes = frame(&body);
        srv_wr.write_all(&bytes[..3]).await.unwrap();
        srv_wr.write_all(&bytes[3..]).await.unwrap();

        let mut hdr = [0u8; 4];
        app_rd.read_exact(&mut hdr).await.unwrap();
        let len = u32::from_be_bytes(hdr) as usize;
        let mut got = vec![0u8; len];
        app_rd.read_exact(&mut got).await.unwrap();
        let mut expected = vec![SSH_FXP_HANDLE, 0, 0, 0, 1];
        put_string(&mut expected, to_wire(b"\xff\x00").as_bytes());
        assert_eq!(got, expected);

        // Client sends a STAT for a GB18030 path; server must see raw bytes.
        let mut body = vec![SSH_FXP_STAT, 0, 0, 0, 2];
        put_string(&mut body, to_wire(b"/\xd6\xd0").as_bytes());
        app_wr.write_all(&frame(&body)).await.unwrap();
        let mut hdr = [0u8; 4];
        srv_rd.read_exact(&mut hdr).await.unwrap();
        let len = u32::from_be_bytes(hdr) as usize;
        let mut got = vec![0u8; len];
        srv_rd.read_exact(&mut got).await.unwrap();
        let mut expected = vec![SSH_FXP_STAT, 0, 0, 0, 2];
        put_string(&mut expected, b"/\xd6\xd0");
        assert_eq!(got, expected);

        // Closing our side propagates EOF to the server side.
        app_wr.shutdown().await.unwrap();
        drop(app_wr);
        let mut rest = Vec::new();
        srv_rd.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }
}
