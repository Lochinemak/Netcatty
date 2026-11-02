//! Identifier helpers.

/// Generate a random, URL-safe identifier (UUID v4 string).
///
/// Matches the shape the renderer already produces with `crypto.randomUUID()`
/// so ids from either side are interchangeable.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Current unix time in milliseconds (JavaScript `Date.now()` compatible).
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_uuid_shaped() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.matches('-').count(), 4);
    }
}
