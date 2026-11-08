//! Context Key expressions (port of `electron/plugins/contextKeys.cjs`).

use crate::error::{PluginError, PluginResult};
use serde_json::{Map, Value};

const MAX_EXPRESSION_LENGTH: usize = 2048;
const MAX_TOKENS: usize = 256;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Op(&'static str),
    Literal(Value),
    Identifier(String),
    In,
    Not,
    Eof,
}

#[derive(Debug, Clone)]
enum Node {
    Literal(Value),
    Key(String),
    Not(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Compare(String, Box<Node>, Box<Node>),
}

fn syntax(message: &str) -> PluginError {
    PluginError::invalid(message)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-')
}

fn tokenize(expression: &str) -> PluginResult<Vec<Token>> {
    if expression.is_empty() || expression.encode_utf16().count() > MAX_EXPRESSION_LENGTH {
        return Err(syntax("Context Key expression length is invalid"));
    }
    let chars: Vec<char> = expression.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let push = |tokens: &mut Vec<Token>, t: Token| -> PluginResult<()> {
        if tokens.len() >= MAX_TOKENS {
            return Err(syntax("Context Key expression is too complex"));
        }
        tokens.push(t);
        Ok(())
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let rest: String = chars[i..].iter().take(3).collect();
        let mut matched = None;
        for op in ["===", "!==", "&&", "||", "==", "!=", ">=", "<=", ">", "<", "!", "(", ")"] {
            if rest.starts_with(op) {
                matched = Some(op);
                break;
            }
        }
        if let Some(op) = matched {
            push(&mut tokens, Token::Op(op))?;
            i += op.chars().count();
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            let mut j = i + 1;
            let mut raw = String::new();
            let mut closed = false;
            while j < chars.len() {
                let ch = chars[j];
                if ch == '\\' {
                    let next = *chars.get(j + 1).ok_or_else(|| syntax("Context Key string is invalid"))?;
                    match next {
                        '"' | '\\' | 'b' | 'f' | 'n' | 'r' | 't' => {
                            raw.push('\\');
                            raw.push(next);
                            j += 2;
                        }
                        '\'' if quote == '\'' => {
                            raw.push('\'');
                            j += 2;
                        }
                        'u' => {
                            let hex: String = chars.iter().skip(j + 2).take(4).collect();
                            if hex.len() != 4 || !hex.chars().all(|h| h.is_ascii_hexdigit()) {
                                return Err(syntax("Context Key string is invalid"));
                            }
                            raw.push_str("\\u");
                            raw.push_str(&hex);
                            j += 6;
                        }
                        _ => return Err(syntax("Context Key string is invalid")),
                    }
                    continue;
                }
                if ch == quote {
                    closed = true;
                    break;
                }
                if quote == '\'' && ch == '"' {
                    raw.push_str("\\\"");
                } else {
                    raw.push(ch);
                }
                j += 1;
            }
            if !closed {
                return Err(syntax("Context Key string is invalid"));
            }
            let value: Value = serde_json::from_str(&format!("\"{raw}\"")).map_err(|_| syntax("Context Key string is invalid"))?;
            push(&mut tokens, Token::Literal(value))?;
            i = j + 1;
            continue;
        }
        // Number vs identifier: the longer match wins (numbers on ties).
        let ident_len = if is_ident_start(c) {
            let mut n = 1;
            while i + n < chars.len() && is_ident(chars[i + n]) && n < 256 {
                n += 1;
            }
            n
        } else {
            0
        };
        let number_len = {
            let mut j = i;
            if j < chars.len() && chars[j] == '-' {
                j += 1;
            }
            let start = j;
            if j < chars.len() && chars[j] == '0' {
                j += 1;
            } else {
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
            }
            if j == start {
                0
            } else {
                if j + 1 < chars.len() && chars[j] == '.' && chars[j + 1].is_ascii_digit() {
                    j += 1;
                    while j < chars.len() && chars[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                j - i
            }
        };
        if number_len > 0 && number_len >= ident_len {
            let text: String = chars[i..i + number_len].iter().collect();
            let number: f64 = text.parse().map_err(|_| syntax("Context Key number is invalid"))?;
            push(&mut tokens, Token::Literal(serde_json::Number::from_f64(number).map(Value::Number).unwrap_or(Value::Null)))?;
            i += number_len;
            continue;
        }
        if ident_len == 0 {
            return Err(syntax(&format!("Unexpected Context Key token at {i}")));
        }
        let word: String = chars[i..i + ident_len].iter().collect();
        i += ident_len;
        let token = match word.as_str() {
            "true" => Token::Literal(Value::Bool(true)),
            "false" => Token::Literal(Value::Bool(false)),
            "null" => Token::Literal(Value::Null),
            "in" => Token::In,
            "not" => Token::Not,
            _ => Token::Identifier(word),
        };
        push(&mut tokens, token)?;
    }
    tokens.push(Token::Eof);
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
}

impl Parser {
    fn current(&self) -> &Token {
        &self.tokens[self.index]
    }
    fn expect_op(&mut self, op: &str) -> PluginResult<()> {
        if self.current() == &Token::Op(match op {
            "(" => "(",
            ")" => ")",
            _ => return Err(syntax("Expected token")),
        }) {
            self.index += 1;
            Ok(())
        } else {
            Err(syntax(&format!("Expected {op}")))
        }
    }
    fn primary(&mut self) -> PluginResult<Node> {
        match self.current().clone() {
            Token::Literal(v) => {
                self.index += 1;
                Ok(Node::Literal(v))
            }
            Token::Identifier(name) => {
                self.index += 1;
                Ok(Node::Key(name))
            }
            Token::Op("(") => {
                self.index += 1;
                let value = self.or()?;
                self.expect_op(")")?;
                Ok(value)
            }
            _ => Err(syntax("Expected Context Key value")),
        }
    }
    fn unary(&mut self) -> PluginResult<Node> {
        if self.current() == &Token::Op("!") {
            self.index += 1;
            return Ok(Node::Not(Box::new(self.unary()?)));
        }
        self.primary()
    }
    fn comparison(&mut self) -> PluginResult<Node> {
        let left = self.unary()?;
        let operator = match self.current().clone() {
            Token::Not if self.tokens.get(self.index + 1) == Some(&Token::In) => {
                self.index += 2;
                "not in".to_string()
            }
            Token::In => {
                self.index += 1;
                "in".to_string()
            }
            Token::Op(op) if ["==", "===", "!=", "!==", ">", ">=", "<", "<="].contains(&op) => {
                self.index += 1;
                op.to_string()
            }
            _ => return Ok(left),
        };
        let right = self.unary()?;
        Ok(Node::Compare(operator, Box::new(left), Box::new(right)))
    }
    fn and(&mut self) -> PluginResult<Node> {
        let mut value = self.comparison()?;
        while self.current() == &Token::Op("&&") {
            self.index += 1;
            value = Node::And(Box::new(value), Box::new(self.comparison()?));
        }
        Ok(value)
    }
    fn or(&mut self) -> PluginResult<Node> {
        let mut value = self.and()?;
        while self.current() == &Token::Op("||") {
            self.index += 1;
            value = Node::Or(Box::new(value), Box::new(self.and()?));
        }
        Ok(value)
    }
}

fn parse(expression: &str) -> PluginResult<Node> {
    let mut parser = Parser { tokens: tokenize(expression)?, index: 0 };
    let node = parser.or()?;
    if parser.current() != &Token::Eof {
        return Err(syntax("Expected eof"));
    }
    Ok(node)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

fn js_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or(0.0);
            if f.fract() == 0.0 && f.abs() < 1e21 {
                format!("{}", f as i64)
            } else {
                f.to_string()
            }
        }
        other => other.to_string(),
    }
}

fn strict_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(_) | Value::Object(_), _) | (_, Value::Array(_) | Value::Object(_)) => false,
        _ => a == b,
    }
}

fn ordered(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64()?.partial_cmp(&y.as_f64()?),
        (Value::String(x), Value::String(y)) => Some(x.encode_utf16().cmp(y.encode_utf16())),
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn contains(container: &Value, item: &Value) -> bool {
    match container {
        Value::Array(items) => items.iter().any(|v| strict_eq(v, item)),
        Value::Object(map) => map.contains_key(&js_string(item)),
        _ => false,
    }
}

fn evaluate(node: &Node, context: &Map<String, Value>) -> Value {
    match node {
        Node::Literal(v) => v.clone(),
        Node::Key(name) => context.get(name).cloned().unwrap_or(Value::Null),
        Node::Not(inner) => Value::Bool(!truthy(&evaluate(inner, context))),
        Node::And(l, r) => Value::Bool(truthy(&evaluate(l, context)) && truthy(&evaluate(r, context))),
        Node::Or(l, r) => Value::Bool(truthy(&evaluate(l, context)) || truthy(&evaluate(r, context))),
        Node::Compare(op, l, r) => {
            // Missing keys are `undefined` in JS; treat as Null but never equal to null literals.
            let missing = |n: &Node| matches!(n, Node::Key(k) if !context.contains_key(k));
            let left = evaluate(l, context);
            let right = evaluate(r, context);
            let result = match op.as_str() {
                "==" | "===" => !(missing(l) ^ missing(r)) && strict_eq(&left, &right),
                "!=" | "!==" => (missing(l) ^ missing(r)) || !strict_eq(&left, &right),
                ">" => ordered(&left, &right) == Some(std::cmp::Ordering::Greater),
                ">=" => matches!(ordered(&left, &right), Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)),
                "<" => ordered(&left, &right) == Some(std::cmp::Ordering::Less),
                "<=" => matches!(ordered(&left, &right), Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)),
                "in" => contains(&right, &left),
                "not in" => !contains(&right, &left),
                _ => false,
            };
            Value::Bool(result)
        }
    }
}

/// `evaluateContextKeyExpression`: empty / missing → true; invalid → false.
pub fn evaluate_expression(expression: Option<&Value>, context: &Map<String, Value>) -> bool {
    let Some(text) = expression.and_then(Value::as_str) else { return true };
    if text.is_empty() {
        return true;
    }
    match parse(text) {
        Ok(node) => truthy(&evaluate(&node, context)),
        Err(_) => false,
    }
}

/// `assertPluginContextKey`.
pub fn assert_plugin_context_key(plugin_id: &str, key: &str) -> PluginResult<String> {
    let prefix = format!("{plugin_id}.");
    let suffix = key.strip_prefix(&prefix).unwrap_or("");
    let full_ok = !key.is_empty()
        && key.len() <= 256
        && key.chars().next().is_some_and(is_ident_start)
        && key.chars().all(is_ident);
    let suffix_ok = !suffix.is_empty()
        && suffix.len() <= 256
        && suffix.chars().next().is_some_and(is_ident_start)
        && suffix.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '-'));
    if !crate::source::is_plugin_id_like(plugin_id) || !full_ok || !suffix_ok {
        return Err(PluginError::invalid(format!("Plugin Context Key must be namespaced to {plugin_id}")));
    }
    Ok(key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Map<String, Value> {
        json!({ "netcatty.surface": "terminal", "count": 3, "list": ["a", "b"], "flag": true })
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn evaluates_expressions() {
        let c = ctx();
        let e = |s: &str| evaluate_expression(Some(&json!(s)), &c);
        assert!(e("netcatty.surface == 'terminal'"));
        assert!(e("netcatty.surface == \"terminal\" && flag"));
        assert!(!e("!flag"));
        assert!(e("count > 2 && count <= 3"));
        assert!(e("'a' in list"));
        assert!(e("'z' not in list"));
        assert!(!e("missing"));
        assert!(e("missing != 'x'"));
        assert!(!e("((("));
        assert!(evaluate_expression(None, &c));
    }

    #[test]
    fn context_key_namespacing() {
        assert!(assert_plugin_context_key("com.example.a", "com.example.a.ready").is_ok());
        assert!(assert_plugin_context_key("com.example.a", "com.other.ready").is_err());
        assert!(assert_plugin_context_key("com.example.a", "com.example.a.x.y").is_err());
    }
}
