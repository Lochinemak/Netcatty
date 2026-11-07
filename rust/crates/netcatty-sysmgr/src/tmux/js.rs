//! Tiny JavaScript value semantics the tmux port relies on (`Number(x)`,
//! `String(x)`, truthiness) so payload handling matches Electron exactly.

use serde_json::{json, Value};

/// `Number(text)` for the strings tmux prints: trimmed, empty → 0,
/// unparsable → NaN (`None`).
pub fn number(text: &str) -> Option<f64> {
    let t = text.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    match t {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    // Rust accepts "inf"/"nan" spellings that JS rejects.
    if t.chars()
        .any(|c| !(c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-')))
    {
        return None;
    }
    t.parse::<f64>().ok()
}

/// `Number(value)` for a JSON payload value.
pub fn value_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => number(s),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Null => Some(0.0),
        _ => None,
    }
}

/// A JS number as JSON: integral values serialize without a fraction,
/// NaN becomes `null` (what `JSON.stringify` does).
pub fn num_json(n: Option<f64>) -> Value {
    match n {
        Some(v) if v.is_finite() && v.fract() == 0.0 && v.abs() < 9.007_199_254_740_992e15 => {
            json!(v as i64)
        }
        Some(v) if v.is_finite() => json!(v),
        _ => Value::Null,
    }
}

/// `Number(text) || 0`.
pub fn num_or_zero(text: &str) -> Value {
    match number(text) {
        Some(v) if v != 0.0 => num_json(Some(v)),
        _ => json!(0),
    }
}

/// `String(n)` for a JS number.
pub fn num_string(n: Option<f64>) -> String {
    match n {
        None => "NaN".to_string(),
        Some(v) if v.is_infinite() => {
            if v > 0.0 {
                "Infinity".to_string()
            } else {
                "-Infinity".to_string()
            }
        }
        Some(v) if v.fract() == 0.0 && v.abs() < 1e21 => format!("{}", v as i64),
        Some(v) => format!("{v}"),
    }
}

/// `String(value)`.
pub fn string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => num_string(n.as_f64()),
        Value::Array(items) => items
            .iter()
            .map(|v| match v {
                Value::Null => String::new(),
                other => string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// JS truthiness of an optional (possibly missing) value.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|v| v != 0.0 && !v.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `value || ""` then `String(...)`.
pub fn string_or_empty(value: Option<&Value>) -> String {
    if truthy(value) {
        value.map(string).unwrap_or_default()
    } else {
        String::new()
    }
}

/// `str.slice(0, n)` (counted in characters).
pub fn slice(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_number_semantics() {
        assert_eq!(number(" 12 "), Some(12.0));
        assert_eq!(number(""), Some(0.0));
        assert_eq!(number("abc"), None);
        assert_eq!(number("inf"), None);
        assert_eq!(num_or_zero("abc"), json!(0));
        assert_eq!(num_or_zero("1718000000"), json!(1718000000));
        assert_eq!(num_json(Some(1.5)), json!(1.5));
        assert_eq!(num_json(None), Value::Null);
        assert_eq!(num_string(value_number(&json!("3"))), "3");
        assert_eq!(num_string(value_number(&json!("x"))), "NaN");
    }

    #[test]
    fn js_string_and_truthiness() {
        assert_eq!(string(&json!(2)), "2");
        assert_eq!(string(&json!(true)), "true");
        assert!(!truthy(Some(&json!(0))));
        assert!(!truthy(Some(&json!(""))));
        assert!(truthy(Some(&json!("0"))));
        assert!(!truthy(None));
        assert_eq!(string_or_empty(Some(&Value::Null)), "");
        assert_eq!(slice("héllo", 2), "hé");
    }
}
