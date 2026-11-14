//! `sftp_find`: a bounded, breadth-first search for entries by name.
//!
//! The walk is written against [`DirLister`] rather than the SFTP client so
//! it runs on one already-open connection in the app and against an
//! in-memory tree in tests. It never follows a symlinked directory (the
//! cheapest way to make loops impossible) and it always terminates: the
//! depth, the number of matches, the number of directories and the time are
//! all capped, and whichever cap stops it is named in the result so the
//! caller narrows the search instead of repeating it.

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub const DEFAULT_MAX_DEPTH: u32 = 5;
pub const MAX_MAX_DEPTH: u32 = 20;
pub const DEFAULT_MAX_RESULTS: usize = 200;
pub const MAX_MAX_RESULTS: usize = 1000;
/// Directories listed before the search gives up.
pub const MAX_DIRECTORIES: usize = 5000;
const MAX_PATTERN_CHARS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

impl EntryKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "file" => Some(Self::File),
            "directory" => Some(Self::Directory),
            "symlink" => Some(Self::Symlink),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }
}

/// One entry of a directory listing.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
    pub size: String,
    pub last_modified: String,
}

/// Lists one remote directory.
#[async_trait::async_trait]
pub trait DirLister: Send + Sync {
    async fn list(&self, path: &str) -> Result<Vec<DirEntry>, String>;
}

#[derive(Debug, Clone)]
pub struct FindOptions {
    pub root: String,
    pub pattern: String,
    pub kind: Option<EntryKind>,
    /// Directory levels searched; `1` is `root` alone.
    pub max_depth: u32,
    pub max_results: usize,
    /// Stop (with what was found) once this much time has passed.
    pub time_budget: Duration,
}

/// A compiled name glob: `*`, `?`, `[abc]`, `[a-z]`, `[!abc]`.
#[derive(Debug)]
pub struct NameGlob(regex::Regex);

impl NameGlob {
    pub fn new(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("pattern is required".into());
        }
        if pattern.chars().count() > MAX_PATTERN_CHARS {
            return Err(format!("pattern is longer than {MAX_PATTERN_CHARS} characters"));
        }
        if pattern.contains('/') {
            return Err("pattern matches entry names, not paths: remove the \"/\" and set path to the directory to search".into());
        }
        let chars: Vec<char> = pattern.chars().collect();
        let mut re = String::from("(?s)^");
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '*' => re.push_str(".*"),
                '?' => re.push('.'),
                '[' => match chars[i + 1..].iter().skip(1).position(|c| *c == ']') {
                    // `skip(1)`: a `]` right after `[` (or `[!`) is a literal member.
                    Some(rel) => {
                        let end = i + 2 + rel;
                        let mut body: String = chars[i + 1..end].iter().collect();
                        let negated = body.starts_with('!') || body.starts_with('^');
                        if negated {
                            body.remove(0);
                        }
                        re.push('[');
                        if negated {
                            re.push('^');
                        }
                        for c in body.chars() {
                            if matches!(c, '\\' | '[' | ']' | '^' | '&' | '~') {
                                re.push('\\');
                            }
                            re.push(c);
                        }
                        re.push(']');
                        i = end;
                    }
                    None => re.push_str("\\["),
                },
                c => re.push_str(&regex::escape(&c.to_string())),
            }
            i += 1;
        }
        re.push('$');
        regex::Regex::new(&re).map(Self).map_err(|_| format!("Invalid pattern: {pattern}"))
    }

    pub fn matches(&self, name: &str) -> bool {
        self.0.is_match(name)
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Search below `opts.root`. `Err` when the pattern is invalid, the root
/// cannot be listed, or the search was cancelled; an unreadable directory
/// further down is skipped and counted.
pub async fn find(lister: &dyn DirLister, opts: &FindOptions, cancel: &CancellationToken) -> Result<Value, String> {
    let glob = NameGlob::new(&opts.pattern)?;
    let max_depth = opts.max_depth.clamp(1, MAX_MAX_DEPTH);
    let max_results = opts.max_results.clamp(1, MAX_MAX_RESULTS);
    let started = tokio::time::Instant::now();
    let root = if opts.root.is_empty() { ".".to_string() } else { opts.root.clone() };

    let mut queue: VecDeque<(String, u32)> = VecDeque::from([(root.clone(), 1)]);
    let mut matches: Vec<Value> = Vec::new();
    let mut scanned = 0usize;
    let mut unreadable = 0usize;
    let mut stopped_by: Option<&'static str> = None;

    'walk: while let Some((dir, depth)) = queue.pop_front() {
        if cancel.is_cancelled() {
            return Err("Cancelled".into());
        }
        if scanned >= MAX_DIRECTORIES {
            stopped_by = Some("directoryLimit");
            break;
        }
        if started.elapsed() >= opts.time_budget {
            stopped_by = Some("timeLimit");
            break;
        }
        let entries = match lister.list(&dir).await {
            Ok(entries) => entries,
            Err(e) if scanned == 0 => return Err(e),
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        scanned += 1;
        for entry in entries {
            if entry.name.is_empty() || entry.name == "." || entry.name == ".." {
                continue;
            }
            let path = join(&dir, &entry.name);
            if opts.kind.is_none_or(|k| k == entry.kind) && glob.matches(&entry.name) {
                if matches.len() >= max_results {
                    stopped_by = Some("maxResults");
                    break 'walk;
                }
                matches.push(json!({ "path": path, "type": entry.kind.as_str(), "size": entry.size, "lastModified": entry.last_modified }));
            }
            if entry.kind == EntryKind::Directory && depth < max_depth {
                queue.push_back((path, depth + 1));
            }
        }
    }

    let mut out = json!({
        "path": root,
        "pattern": opts.pattern,
        "matches": matches,
        "matchCount": matches.len(),
        "truncated": stopped_by.is_some(),
        "directoriesScanned": scanned,
        "unreadableDirectories": unreadable,
    });
    if let Some(reason) = stopped_by {
        out["truncatedBy"] = json!(reason);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// An in-memory tree: directory path → entries.
    #[derive(Default)]
    struct Tree {
        dirs: HashMap<String, Vec<(&'static str, EntryKind)>>,
        denied: Vec<String>,
        listed: parking_lot::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl DirLister for Tree {
        async fn list(&self, path: &str) -> Result<Vec<DirEntry>, String> {
            self.listed.lock().push(path.to_string());
            if self.denied.iter().any(|d| d == path) {
                return Err("Permission denied".into());
            }
            let entries = self.dirs.get(path).ok_or_else(|| format!("No such file: {path}"))?;
            Ok(entries.iter().map(|(name, kind)| DirEntry { name: (*name).into(), kind: *kind, size: "1".into(), last_modified: String::new() }).collect())
        }
    }

    use EntryKind::{Directory as D, File as F, Symlink as L};

    fn tree() -> Tree {
        let mut dirs = HashMap::new();
        dirs.insert("/etc".to_string(), vec![(".", D), ("..", D), ("nginx", D), ("hosts", F), ("app.conf", F), ("secret", D), ("loop", L)]);
        dirs.insert("/etc/nginx".to_string(), vec![("nginx.conf", F), ("conf.d", D), ("mime.types", F)]);
        dirs.insert("/etc/nginx/conf.d".to_string(), vec![("default.conf", F), ("deep", D)]);
        dirs.insert("/etc/nginx/conf.d/deep".to_string(), vec![("buried.conf", F)]);
        Tree { dirs, denied: vec!["/etc/secret".into()], ..Default::default() }
    }

    fn opts(root: &str, pattern: &str) -> FindOptions {
        FindOptions { root: root.into(), pattern: pattern.into(), kind: None, max_depth: DEFAULT_MAX_DEPTH, max_results: DEFAULT_MAX_RESULTS, time_budget: Duration::from_secs(60) }
    }

    fn paths(result: &Value) -> Vec<String> {
        result["matches"].as_array().unwrap().iter().map(|m| m["path"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn glob_matches_whole_names() {
        let m = |p: &str, n: &str| NameGlob::new(p).unwrap().matches(n);
        assert!(m("*.conf", "nginx.conf") && !m("*.conf", "nginx.conf.bak"));
        assert!(m("nginx", "nginx") && !m("nginx", "nginx.conf"));
        assert!(m("*nginx*", "my-nginx.conf"));
        assert!(m("file?.txt", "file1.txt") && !m("file?.txt", "file12.txt"));
        assert!(m("[a-c]at", "bat") && !m("[a-c]at", "rat"));
        assert!(m("[!a-c]at", "rat") && !m("[!a-c]at", "bat"));
        // Regex metacharacters in a name are literal.
        assert!(m("a+b(1).txt", "a+b(1).txt") && !m("a.b", "axb"));
        assert!(m("[]x]", "]") && m("data[", "data["));
        assert!(m("*", ".hidden"));
        assert!(NameGlob::new("").is_err());
        assert!(NameGlob::new("conf.d/*.conf").unwrap_err().contains("not paths"));
        assert!(NameGlob::new(&"a".repeat(MAX_PATTERN_CHARS + 1)).is_err());
    }

    #[tokio::test]
    async fn finds_recursively_skipping_unreadable_and_symlinked_directories() {
        let t = tree();
        let r = find(&t, &opts("/etc", "*.conf"), &CancellationToken::new()).await.unwrap();
        assert_eq!(paths(&r), ["/etc/app.conf", "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf", "/etc/nginx/conf.d/deep/buried.conf"]);
        assert_eq!(r["truncated"], false);
        assert_eq!(r["unreadableDirectories"], 1);
        assert_eq!(r["directoriesScanned"], 4);
        assert!(r.get("truncatedBy").is_none());
        // `loop` is a symlink: listed as an entry, never descended into.
        assert!(!t.listed.lock().iter().any(|p| p == "/etc/loop"));
        assert_eq!(r["matches"][0]["type"], "file");
    }

    #[tokio::test]
    async fn depth_type_and_result_limits() {
        let t = tree();
        let token = CancellationToken::new();
        let r = find(&t, &FindOptions { max_depth: 1, ..opts("/etc", "*") }, &token).await.unwrap();
        assert_eq!(paths(&r), ["/etc/nginx", "/etc/hosts", "/etc/app.conf", "/etc/secret", "/etc/loop"]);
        assert_eq!(t.listed.lock().as_slice(), ["/etc"]);
        let r = find(&t, &FindOptions { max_depth: 2, ..opts("/etc", "*.conf") }, &token).await.unwrap();
        assert_eq!(paths(&r), ["/etc/app.conf", "/etc/nginx/nginx.conf"]);
        let r = find(&t, &FindOptions { kind: Some(D), ..opts("/etc", "*") }, &token).await.unwrap();
        assert_eq!(paths(&r), ["/etc/nginx", "/etc/secret", "/etc/nginx/conf.d", "/etc/nginx/conf.d/deep"]);
        let r = find(&t, &FindOptions { kind: Some(L), ..opts("/etc", "*") }, &token).await.unwrap();
        assert_eq!(paths(&r), ["/etc/loop"]);
        let r = find(&t, &FindOptions { max_results: 2, ..opts("/etc", "*.conf") }, &token).await.unwrap();
        assert_eq!(paths(&r).len(), 2);
        assert_eq!((r["truncated"].clone(), r["truncatedBy"].clone()), (json!(true), json!("maxResults")));
        // Exactly as many matches as the limit is not a truncation.
        let r = find(&t, &FindOptions { max_results: 4, ..opts("/etc", "*.conf") }, &token).await.unwrap();
        assert_eq!(r["truncated"], false);
        let r = find(&t, &opts("/", "x"), &token).await;
        assert_eq!(r.unwrap_err(), "No such file: /");
    }

    #[tokio::test]
    async fn stops_on_time_budget_and_cancellation() {
        let t = tree();
        let r = find(&t, &FindOptions { time_budget: Duration::ZERO, ..opts("/etc", "*") }, &CancellationToken::new()).await.unwrap();
        assert_eq!((r["truncatedBy"].clone(), r["matchCount"].clone()), (json!("timeLimit"), json!(0)));
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(find(&t, &opts("/etc", "*"), &token).await.unwrap_err(), "Cancelled");
        assert_eq!(join("/", "etc"), "/etc");
    }
}
