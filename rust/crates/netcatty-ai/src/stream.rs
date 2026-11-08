//! Streaming chat proxy (`netcatty:ai:chat:stream`, Electron `aiBridge.cjs`
//! `streamRequest`). The returned future resolves as soon as the response
//! headers arrive (with the real status) so the renderer can build a
//! `Response`; the body then flows through the [`StreamSink`] as
//! `netcatty:ai:stream:data` / `:end` / `:error` events, one SSE `data:`
//! payload per event.
//!
//! Deadlines: the stream aborts after `idle` milliseconds without bytes
//! (thinking tokens re-arm the timer, issue #3051) and after `total`
//! milliseconds overall. Non-2xx responses are read (bounded) so the error
//! message can be extracted and reported.

use crate::http::{client, describe_error, header_map, method, Utf8Decoder};
use crate::providers::Headers;
use crate::sse::extract_sse_data_payload;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Total deadline: long enough for extended reasoning.
pub const DEFAULT_AI_STREAM_TOTAL_TIMEOUT_MS: u64 = 30 * 60 * 1000;
/// Abort only after this much silence.
pub const DEFAULT_AI_STREAM_IDLE_TIMEOUT_MS: u64 = 2 * 60 * 1000;
pub const MAX_AI_STREAM_IDLE_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
pub const AI_STREAM_IDLE_TOTAL_HEADROOM_MS: u64 = 90 * 1000;
/// Error bodies of non-2xx responses are read up to this many bytes by default.
pub const DEFAULT_MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
/// Pending (unterminated) SSE line buffer cap.
pub const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamTimeouts {
    pub idle_ms: u64,
    pub total_ms: u64,
}

/// Electron `resolveAIStreamTimeouts`: clamp the requested idle timeout and
/// make sure the total deadline never undercuts it.
pub fn resolve_stream_timeouts(idle_timeout_ms: Option<f64>, total_timeout_ms: Option<f64>) -> StreamTimeouts {
    let explicit_idle = idle_timeout_ms.filter(|v| v.is_finite());
    let idle_ms = explicit_idle
        .map(|v| v.max(1.0).min(MAX_AI_STREAM_IDLE_TIMEOUT_MS as f64) as u64)
        .unwrap_or(DEFAULT_AI_STREAM_IDLE_TIMEOUT_MS);
    let total_budget_ms = total_timeout_ms
        .filter(|v| v.is_finite() && *v > 0.0)
        .map(|v| v as u64)
        .unwrap_or(DEFAULT_AI_STREAM_TOTAL_TIMEOUT_MS);
    let total_ms = if explicit_idle.is_some() {
        total_budget_ms.max(idle_ms + AI_STREAM_IDLE_TOTAL_HEADROOM_MS)
    } else {
        total_budget_ms
    };
    StreamTimeouts { idle_ms, total_ms }
}

#[derive(Debug, Clone, Default)]
pub struct StreamOptions {
    /// Defaults to `POST`.
    pub method: Option<String>,
    pub headers: Headers,
    pub body: Option<String>,
    pub idle_timeout_ms: Option<f64>,
    pub total_timeout_ms: Option<f64>,
    pub max_error_body_bytes: Option<usize>,
    pub skip_tls_verify: bool,
}

/// Receives the stream events for one request.
pub trait StreamSink: Send + Sync + 'static {
    /// One SSE `data:` payload (`netcatty:ai:stream:data`).
    fn data(&self, payload: String);
    /// Clean end of the body (`netcatty:ai:stream:end`).
    fn end(&self);
    /// Failure, including aborts and HTTP errors (`netcatty:ai:stream:error`).
    fn error(&self, message: String);
    /// Called exactly once when the request lifecycle is over (after `end`
    /// or `error`, or when the request failed before any headers arrived).
    fn finished(&self) {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// Cancelled through the token (`AbortError`).
    Aborted,
    /// Any other failure; the message was also sent to the sink.
    Failed(String),
}

impl StreamError {
    pub fn message(&self) -> String {
        match self {
            StreamError::Aborted => "Aborted".into(),
            StreamError::Failed(message) => message.clone(),
        }
    }
}

/// Resolved once the response headers have arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamStarted {
    pub status_code: u16,
    pub status_text: String,
}

enum Next {
    Chunk(bytes::Bytes),
    Eof,
    Cancelled,
    Idle,
    Total,
    Error(String),
}

async fn next_chunk(
    response: &mut reqwest::Response,
    idle: Duration,
    total_deadline: Instant,
    cancel: &CancellationToken,
) -> Next {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Next::Cancelled,
        _ = tokio::time::sleep_until(total_deadline) => Next::Total,
        _ = tokio::time::sleep(idle) => Next::Idle,
        chunk = response.chunk() => match chunk {
            Ok(Some(bytes)) => Next::Chunk(bytes),
            Ok(None) => Next::Eof,
            Err(err) => Next::Error(describe_error(&err)),
        },
    }
}

fn idle_message(idle_ms: u64) -> String {
    format!("AI stream idle deadline exceeded after {idle_ms} ms")
}

fn total_message(total_ms: u64) -> String {
    format!("AI stream total deadline exceeded after {total_ms} ms")
}

/// Error detail of a non-2xx body: OpenAI-compatible `error.message`,
/// `message` or `detail`, else the first 500 characters of the body, else
/// the status text.
fn error_detail(body: &str, status_text: &str) -> String {
    fn truthy_string(value: Option<&serde_json::Value>) -> Option<String> {
        match value? {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            serde_json::Value::Null | serde_json::Value::String(_) => None,
            serde_json::Value::Bool(false) => None,
            serde_json::Value::Number(n) if n.as_f64() == Some(0.0) => None,
            other => Some(other.to_string()),
        }
    }
    let head: String = body.chars().take(500).collect();
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(parsed) => truthy_string(parsed.get("error").and_then(|e| e.get("message")))
            .or_else(|| truthy_string(parsed.get("message")))
            .or_else(|| truthy_string(parsed.get("detail")))
            .unwrap_or_else(|| if head.is_empty() { status_text.to_owned() } else { head }),
        Err(_) => {
            if body.trim().is_empty() {
                status_text.to_owned()
            } else {
                head
            }
        }
    }
}

/// Start the request. Resolves with the status once headers arrive; the
/// body is pumped on a background task that reports through `sink`.
/// Errors before the headers are reported both through `sink.error` and
/// the returned `Err`.
pub async fn stream_request(
    url: String,
    options: StreamOptions,
    sink: Arc<dyn StreamSink>,
    cancel: CancellationToken,
) -> Result<StreamStarted, StreamError> {
    let timeouts = resolve_stream_timeouts(options.idle_timeout_ms, options.total_timeout_ms);
    let idle = Duration::from_millis(timeouts.idle_ms);
    let total_deadline = Instant::now() + Duration::from_millis(timeouts.total_ms);
    let max_error_body_bytes = options.max_error_body_bytes.unwrap_or(DEFAULT_MAX_ERROR_BODY_BYTES).max(1);

    let fail = |sink: &Arc<dyn StreamSink>, message: String| -> Result<StreamStarted, StreamError> {
        sink.error(message.clone());
        sink.finished();
        Err(StreamError::Failed(message))
    };
    let abort = |sink: &Arc<dyn StreamSink>| -> Result<StreamStarted, StreamError> {
        sink.error("Aborted".into());
        sink.finished();
        Err(StreamError::Aborted)
    };

    if cancel.is_cancelled() {
        return abort(&sink);
    }
    let http = match client(options.skip_tls_verify) {
        Ok(client) => client,
        Err(err) => return fail(&sink, err.message),
    };
    let mut builder = http
        .request(method(options.method.as_deref(), reqwest::Method::POST), &url)
        .headers(header_map(&options.headers));
    if let Some(body) = options.body.filter(|b| !b.is_empty()) {
        builder = builder.body(body);
    }
    let send = builder.send();
    let mut response = tokio::select! {
        biased;
        _ = cancel.cancelled() => return abort(&sink),
        _ = tokio::time::sleep_until(total_deadline) => return fail(&sink, total_message(timeouts.total_ms)),
        _ = tokio::time::sleep(idle) => return fail(&sink, idle_message(timeouts.idle_ms)),
        result = send => match result {
            Ok(response) => response,
            Err(err) => return fail(&sink, describe_error(&err)),
        },
    };

    let status = response.status();
    let status_code = status.as_u16();
    let status_text = status.canonical_reason().unwrap_or("").to_owned();

    if !status.is_success() {
        // Read the error body before resolving so the message can be included.
        let mut error_body: Vec<u8> = Vec::new();
        loop {
            match next_chunk(&mut response, idle, total_deadline, &cancel).await {
                Next::Chunk(bytes) => {
                    if error_body.len() + bytes.len() > max_error_body_bytes {
                        return fail(
                            &sink,
                            format!("AI error response exceeded maximum size ({max_error_body_bytes} bytes)"),
                        );
                    }
                    error_body.extend_from_slice(&bytes);
                }
                Next::Eof => break,
                Next::Cancelled => return abort(&sink),
                Next::Idle => return fail(&sink, idle_message(timeouts.idle_ms)),
                Next::Total => return fail(&sink, total_message(timeouts.total_ms)),
                Next::Error(message) => return fail(&sink, message),
            }
        }
        let detail = error_detail(&String::from_utf8_lossy(&error_body), &status_text);
        sink.error(format!("HTTP {status_code}: {detail}"));
        sink.finished();
        return Ok(StreamStarted { status_code, status_text: format!("{status_code} {detail}") });
    }

    // Resolve with the success status — data flows via the sink.
    let started = StreamStarted { status_code, status_text };
    tokio::spawn(async move {
        let mut decoder = Utf8Decoder::default();
        let mut buffer = String::new();
        loop {
            match next_chunk(&mut response, idle, total_deadline, &cancel).await {
                Next::Chunk(bytes) => {
                    let previous_len = buffer.len();
                    buffer.push_str(&decoder.push(&bytes));
                    if buffer.len() > MAX_BUFFER_SIZE {
                        sink.error("Stream buffer exceeded maximum size (10MB)".into());
                        sink.finished();
                        return;
                    }
                    let mut consumed = 0;
                    let mut search_from = previous_len;
                    while let Some(offset) = buffer[search_from..].find('\n') {
                        let newline = search_from + offset;
                        if let Some(payload) = extract_sse_data_payload(&buffer[consumed..newline]) {
                            sink.data(payload);
                        }
                        consumed = newline + 1;
                        search_from = consumed;
                    }
                    if consumed > 0 {
                        buffer.drain(..consumed);
                    }
                }
                Next::Eof => {
                    buffer.push_str(&decoder.finish());
                    // Flush any remaining buffer.
                    if let Some(payload) = extract_sse_data_payload(&buffer) {
                        sink.data(payload);
                    }
                    sink.end();
                    sink.finished();
                    return;
                }
                Next::Cancelled => {
                    sink.error("Aborted".into());
                    sink.finished();
                    return;
                }
                Next::Idle => {
                    sink.error(idle_message(timeouts.idle_ms));
                    sink.finished();
                    return;
                }
                Next::Total => {
                    sink.error(total_message(timeouts.total_ms));
                    sink.finished();
                    return;
                }
                Next::Error(message) => {
                    sink.error(message);
                    sink.finished();
                    return;
                }
            }
        }
    });
    Ok(started)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{serve_once, ScriptedResponse};
    use std::sync::Mutex;

    #[derive(Debug, PartialEq, Clone)]
    enum Event {
        Data(String),
        End,
        Error(String),
        Finished,
    }

    #[derive(Default)]
    struct Collector {
        events: Mutex<Vec<Event>>,
        notify: tokio::sync::Notify,
    }

    impl Collector {
        fn push(&self, event: Event) {
            self.events.lock().unwrap().push(event);
            self.notify.notify_waiters();
        }
        async fn wait_finished(&self) -> Vec<Event> {
            loop {
                let notified = self.notify.notified();
                {
                    let events = self.events.lock().unwrap();
                    if events.contains(&Event::Finished) {
                        return events.clone();
                    }
                }
                tokio::time::timeout(Duration::from_secs(5), notified).await.expect("stream finished");
            }
        }
    }

    impl StreamSink for Collector {
        fn data(&self, payload: String) {
            self.push(Event::Data(payload));
        }
        fn end(&self) {
            self.push(Event::End);
        }
        fn error(&self, message: String) {
            self.push(Event::Error(message));
        }
        fn finished(&self) {
            self.push(Event::Finished);
        }
    }

    const SSE_HEAD: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";

    fn options() -> StreamOptions {
        StreamOptions {
            headers: [("content-type".to_owned(), "application/json".to_owned())].into_iter().collect(),
            body: Some("{\"stream\":true}".into()),
            ..StreamOptions::default()
        }
    }

    #[test]
    fn timeouts_match_electron() {
        assert_eq!(DEFAULT_AI_STREAM_IDLE_TIMEOUT_MS, 120_000);
        assert_eq!(DEFAULT_AI_STREAM_TOTAL_TIMEOUT_MS, 30 * 60 * 1000);
        let defaults = resolve_stream_timeouts(None, None);
        assert_eq!(defaults, StreamTimeouts { idle_ms: 120_000, total_ms: 30 * 60 * 1000 });
        // The total deadline never undercuts the configured idle timeout.
        let long_idle = resolve_stream_timeouts(Some(60.0 * 60.0 * 1000.0), Some(30.0 * 60.0 * 1000.0));
        assert_eq!(long_idle.idle_ms, 60 * 60 * 1000);
        assert!(long_idle.total_ms > long_idle.idle_ms);
        assert_eq!(resolve_stream_timeouts(Some(0.0), None).idle_ms, 1);
        assert_eq!(resolve_stream_timeouts(Some(f64::NAN), None).idle_ms, DEFAULT_AI_STREAM_IDLE_TIMEOUT_MS);
        assert_eq!(resolve_stream_timeouts(Some(1e12), None).idle_ms, MAX_AI_STREAM_IDLE_TIMEOUT_MS);
    }

    #[tokio::test]
    async fn utf8_split_across_chunks_and_content_length() {
        let message = "data: {\"choices\":[{\"delta\":{\"content\":\"环境正常\"}}]}\n\n".as_bytes().to_vec();
        let split = message.iter().position(|&b| b == b'\xe7').unwrap() + 1;
        let (base, received) = serve_once(vec![ScriptedResponse::parts(vec![
            (Duration::ZERO, SSE_HEAD.as_bytes().to_vec()),
            (Duration::ZERO, message[..split].to_vec()),
            (Duration::from_millis(20), message[split..].to_vec()),
        ])])
        .await;
        let sink = Arc::new(Collector::default());
        let started = stream_request(format!("{base}/v1/chat/completions"), options(), sink.clone(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(started, StreamStarted { status_code: 200, status_text: "OK".into() });
        let events = sink.wait_finished().await;
        assert_eq!(
            events,
            vec![
                Event::Data("{\"choices\":[{\"delta\":{\"content\":\"环境正常\"}}]}".into()),
                Event::End,
                Event::Finished
            ]
        );
        let request = String::from_utf8_lossy(&received.await.unwrap()).to_ascii_lowercase();
        assert!(request.starts_with("post /v1/chat/completions"));
        assert!(request.contains("content-length: 15"), "{request}");
        assert!(!request.contains("transfer-encoding"));
    }

    #[tokio::test]
    async fn accepts_data_without_space_and_flushes_a_trailing_line() {
        let (base, _) = serve_once(vec![ScriptedResponse::parts(vec![
            (Duration::ZERO, SSE_HEAD.as_bytes().to_vec()),
            (Duration::ZERO, b"data:{\"a\":1}\r\n\r\nevent: ping\n".to_vec()),
            (Duration::from_millis(10), b"data:{\"b\":2}".to_vec()),
        ])])
        .await;
        let sink = Arc::new(Collector::default());
        stream_request(format!("{base}/x"), options(), sink.clone(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            sink.wait_finished().await,
            vec![
                Event::Data("{\"a\":1}".into()),
                Event::Data("{\"b\":2}".into()),
                Event::End,
                Event::Finished
            ]
        );
    }

    #[tokio::test]
    async fn non_2xx_reports_the_extracted_error_and_status_text() {
        let (base, _) = serve_once(vec![ScriptedResponse::text(
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":{\"message\":\"Invalid API key\"}}",
        )])
        .await;
        let sink = Arc::new(Collector::default());
        let started = stream_request(format!("{base}/x"), options(), sink.clone(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(started, StreamStarted { status_code: 401, status_text: "401 Invalid API key".into() });
        assert_eq!(
            sink.wait_finished().await,
            vec![Event::Error("HTTP 401: Invalid API key".into()), Event::Finished]
        );
        assert_eq!(error_detail("", "Bad Gateway"), "Bad Gateway");
        assert_eq!(error_detail("plain text failure", "Bad Gateway"), "plain text failure");
        assert_eq!(error_detail("{\"detail\":\"d\"}", "x"), "d");
        assert_eq!(error_detail("{\"message\":\"m\"}", "x"), "m");
        assert_eq!(error_detail("{\"other\":1}", "x"), "{\"other\":1}");
    }

    #[tokio::test]
    async fn non_2xx_bodies_are_bounded_and_terminated() {
        let mut parts = vec![(Duration::ZERO, b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n".to_vec())];
        for _ in 0..50 {
            parts.push((Duration::from_millis(2), b"abcdefgh".to_vec()));
        }
        let (base, _) = serve_once(vec![ScriptedResponse::parts(parts)]).await;
        let sink = Arc::new(Collector::default());
        let err = stream_request(
            format!("{base}/streaming-error"),
            StreamOptions { max_error_body_bytes: Some(32), total_timeout_ms: Some(1_000.0), ..options() },
            sink.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(&err, StreamError::Failed(m) if m.contains("error response exceeded")), "{err:?}");
        let events = sink.wait_finished().await;
        assert!(matches!(&events[0], Event::Error(m) if m.contains("error response exceeded")));
    }

    #[tokio::test]
    async fn idle_deadline_aborts_a_silent_stream_but_not_an_active_one() {
        let (base, _) = serve_once(vec![ScriptedResponse::parts(vec![
            (Duration::ZERO, SSE_HEAD.as_bytes().to_vec()),
            (Duration::from_millis(30), b"data: 1\n".to_vec()),
            (Duration::from_millis(30), b"data: 2\n".to_vec()),
            (Duration::from_millis(400), b"data: 3\n".to_vec()),
        ])])
        .await;
        let sink = Arc::new(Collector::default());
        stream_request(
            format!("{base}/x"),
            StreamOptions { idle_timeout_ms: Some(150.0), ..options() },
            sink.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            sink.wait_finished().await,
            vec![
                Event::Data("1".into()),
                Event::Data("2".into()),
                Event::Error("AI stream idle deadline exceeded after 150 ms".into()),
                Event::Finished
            ]
        );
    }

    #[tokio::test]
    async fn total_deadline_applies_even_while_bytes_keep_arriving() {
        let mut parts = vec![(Duration::ZERO, SSE_HEAD.as_bytes().to_vec())];
        for i in 0..100 {
            parts.push((Duration::from_millis(10), format!("data: {i}\n").into_bytes()));
        }
        let (base, _) = serve_once(vec![ScriptedResponse::parts(parts)]).await;
        let sink = Arc::new(Collector::default());
        stream_request(
            format!("{base}/x"),
            StreamOptions { total_timeout_ms: Some(200.0), ..options() },
            sink.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let events = sink.wait_finished().await;
        assert!(events.iter().any(|e| matches!(e, Event::Error(m) if m.contains("total deadline"))), "{events:?}");
        assert!(!events.contains(&Event::End));
    }

    #[tokio::test]
    async fn cancellation_aborts_before_and_after_headers() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let sink = Arc::new(Collector::default());
        assert_eq!(
            stream_request("http://127.0.0.1:1/x".into(), options(), sink.clone(), cancel).await,
            Err(StreamError::Aborted)
        );
        assert_eq!(sink.wait_finished().await, vec![Event::Error("Aborted".into()), Event::Finished]);

        let (base, _) = serve_once(vec![ScriptedResponse::parts(vec![
            (Duration::ZERO, SSE_HEAD.as_bytes().to_vec()),
            (Duration::from_millis(2_000), b"data: late\n".to_vec()),
        ])])
        .await;
        let cancel = CancellationToken::new();
        let sink = Arc::new(Collector::default());
        stream_request(format!("{base}/x"), options(), sink.clone(), cancel.clone()).await.unwrap();
        cancel.cancel();
        assert_eq!(sink.wait_finished().await, vec![Event::Error("Aborted".into()), Event::Finished]);
    }

    #[tokio::test]
    async fn connection_failures_fail_before_headers() {
        let sink = Arc::new(Collector::default());
        let err = stream_request("http://127.0.0.1:1/x".into(), options(), sink.clone(), CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::Failed(_)));
        let events = sink.wait_finished().await;
        assert!(matches!(events[0], Event::Error(_)));
    }
}
