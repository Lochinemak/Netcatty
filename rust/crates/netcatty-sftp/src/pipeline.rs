//! Pipelined SFTP reads and writes on a raw session.
//!
//! `RawSftpSession` exposes one request per call; throughput over a
//! high-latency link needs several requests in flight. These helpers keep
//! up to `depth` outstanding `READ`/`WRITE` requests and hand results back in
//! order, filling short reads so the consumer always sees a contiguous byte
//! stream.

use crate::error::SftpResult;
use russh_sftp::client::error::Error as RawError;
use russh_sftp::client::RawSftpSession;
use russh_sftp::protocol::{Data, Status, StatusCode};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

type BoxFut<T> = Pin<Box<dyn Future<Output = Result<T, RawError>> + Send>>;

/// Outstanding requests per direction.
pub(crate) const PIPELINE_DEPTH: usize = 8;

/// In-order, read-ahead reader over an open SFTP file handle.
pub(crate) struct PipelinedReader {
    session: Arc<RawSftpSession>,
    handle: String,
    /// Next offset to *request*.
    next_offset: u64,
    /// Do not request past this offset (known file size), if any.
    end: Option<u64>,
    chunk: u32,
    depth: usize,
    inflight: VecDeque<(u64, u32, BoxFut<Data>)>,
    eof: bool,
}

impl PipelinedReader {
    pub fn new(
        session: Arc<RawSftpSession>,
        handle: String,
        start: u64,
        end: Option<u64>,
        chunk: u32,
        depth: usize,
    ) -> Self {
        Self {
            session,
            handle,
            next_offset: start,
            end,
            chunk: chunk.max(1),
            depth: depth.max(1),
            inflight: VecDeque::new(),
            eof: false,
        }
    }

    fn request(&self, offset: u64, len: u32) -> BoxFut<Data> {
        let session = self.session.clone();
        let handle = self.handle.clone();
        Box::pin(async move { session.read(handle, offset, len).await })
    }

    fn fill(&mut self) {
        while !self.eof && self.inflight.len() < self.depth {
            let len = match self.end {
                Some(end) if self.next_offset >= end => break,
                Some(end) => (end - self.next_offset).min(self.chunk as u64) as u32,
                None => self.chunk,
            };
            let fut = self.request(self.next_offset, len);
            self.inflight.push_back((self.next_offset, len, fut));
            self.next_offset += len as u64;
        }
    }

    /// Next contiguous chunk, or `None` at end of file.
    pub async fn next_chunk(&mut self) -> SftpResult<Option<Vec<u8>>> {
        self.fill();
        let Some((offset, len, fut)) = self.inflight.pop_front() else {
            return Ok(None);
        };
        match fut.await {
            Ok(data) => {
                if data.data.is_empty() {
                    self.eof = true;
                    self.inflight.clear();
                    return Ok(None);
                }
                let got = data.data.len() as u32;
                if got < len {
                    // Short read: fetch the gap before anything already queued.
                    let gap_offset = offset + got as u64;
                    let gap = self.request(gap_offset, len - got);
                    self.inflight.push_front((gap_offset, len - got, gap));
                }
                Ok(Some(data.data))
            }
            Err(RawError::Status(status)) if status.status_code == StatusCode::Eof => {
                self.eof = true;
                self.inflight.clear();
                Ok(None)
            }
            Err(err) => {
                self.inflight.clear();
                Err(err.into())
            }
        }
    }
}

/// Sequential writer that keeps several `WRITE` requests in flight.
pub(crate) struct PipelinedWriter {
    session: Arc<RawSftpSession>,
    handle: String,
    /// Offset of the next byte to be written.
    offset: u64,
    /// Bytes the server has acknowledged, contiguous from the start.
    acked: u64,
    chunk: u32,
    depth: usize,
    inflight: VecDeque<(u64, BoxFut<Status>)>,
}

impl PipelinedWriter {
    pub fn new(
        session: Arc<RawSftpSession>,
        handle: String,
        start: u64,
        chunk: u32,
        depth: usize,
    ) -> Self {
        Self {
            session,
            handle,
            offset: start,
            acked: start,
            chunk: chunk.max(1),
            depth: depth.max(1),
            inflight: VecDeque::new(),
        }
    }

    /// Bytes confirmed by the server (safe resume checkpoint).
    pub fn acknowledged(&self) -> u64 {
        self.acked
    }

    async fn await_oldest(&mut self) -> SftpResult<()> {
        if let Some((end, fut)) = self.inflight.pop_front() {
            match fut.await {
                Ok(_) => self.acked = end,
                Err(err) => {
                    self.inflight.clear();
                    return Err(err.into());
                }
            }
        }
        Ok(())
    }

    /// Queue `data` (split into server-sized pieces), waiting only when the
    /// pipeline is full.
    pub async fn write(&mut self, data: &[u8]) -> SftpResult<()> {
        for piece in data.chunks(self.chunk as usize) {
            if self.inflight.len() >= self.depth {
                self.await_oldest().await?;
            }
            let session = self.session.clone();
            let handle = self.handle.clone();
            let offset = self.offset;
            let buf = piece.to_vec();
            let end = offset + piece.len() as u64;
            self.inflight.push_back((
                end,
                Box::pin(async move { session.write(handle, offset, buf).await }),
            ));
            self.offset = end;
        }
        Ok(())
    }

    /// Wait for every outstanding write.
    pub async fn flush(&mut self) -> SftpResult<()> {
        while !self.inflight.is_empty() {
            self.await_oldest().await?;
        }
        Ok(())
    }
}

/// Close a handle, ignoring errors (used on error/cancel paths).
pub(crate) async fn close_quietly(session: &RawSftpSession, handle: &str) {
    if let Err(err) = session.close(handle).await {
        tracing::debug!(error = %err, "sftp close failed");
    }
}
