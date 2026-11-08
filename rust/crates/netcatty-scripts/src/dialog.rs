//! Dialog form specification normalization (`normalizeDialogFormSpec` in
//! `electron/scripts/scriptRuntime.cjs`). Error messages are the ones the
//! script sees.

use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// `String(value)` for the JSON values a script can pass.
pub fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number_string(n.as_f64().unwrap_or(0.0)),
        Value::Array(items) => items.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// `String(number)` for finite numbers (integers without a fraction).
pub fn js_number_string(n: f64) -> String {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{}", n as i64)
    } else {
        n.to_string()
    }
}

/// `Number(value)` for a JSON value; `None` stands for `NaN`.
pub fn js_number(value: &Value) -> Option<f64> {
    match value {
        Value::Null => Some(0.0),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Some(0.0)
            } else {
                trimmed.parse::<f64>().ok()
            }
        }
        Value::Array(items) if items.is_empty() => Some(0.0),
        Value::Array(items) if items.len() == 1 => js_number(&items[0]),
        _ => None,
    }
}

/// JS truthiness.
pub fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `value == null` (null or absent / undefined).
fn is_nullish(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

fn opt_string(value: Option<&Value>) -> Option<String> {
    if is_nullish(value) {
        None
    } else {
        value.map(js_string)
    }
}

fn normalize_dialog_option(option: &Value) -> Result<Value, String> {
    if let Value::String(text) = option {
        if text.is_empty() {
            return Err("Dialog option value is required".into());
        }
        return Ok(json!({
            "label": text,
            "value": text,
            "disabled": false,
        }));
    }
    let Value::Object(map) = option else {
        return Err("Dialog option must be a string or object".into());
    };
    let value = opt_string(map.get("value")).unwrap_or_default();
    if value.is_empty() {
        return Err("Dialog option value is required".into());
    }
    let mut out = Map::new();
    out.insert(
        "label".into(),
        Value::String(opt_string(map.get("label")).unwrap_or_else(|| value.clone())),
    );
    out.insert("value".into(), Value::String(value));
    if let Some(description) = opt_string(map.get("description")) {
        out.insert("description".into(), Value::String(description));
    }
    out.insert(
        "disabled".into(),
        Value::Bool(map.get("disabled").is_some_and(js_truthy)),
    );
    Ok(Value::Object(out))
}

fn normalize_choice_options(
    field_type: &str,
    options: Option<&Value>,
    default_value: Option<&Value>,
) -> Result<(Vec<Value>, String), String> {
    let Some(Value::Array(options)) = options else {
        return Err(format!(
            "Dialog {field_type} field requires at least one option"
        ));
    };
    if options.is_empty() {
        return Err(format!(
            "Dialog {field_type} field requires at least one option"
        ));
    }
    let normalized: Vec<Value> = options
        .iter()
        .map(normalize_dialog_option)
        .collect::<Result<_, _>>()?;
    let mut seen = HashSet::new();
    for option in &normalized {
        let value = option["value"].as_str().unwrap_or("").to_string();
        if !seen.insert(value.clone()) {
            return Err(format!(
                "Dialog {field_type} field option values must be unique: {value}"
            ));
        }
    }
    let first_enabled = normalized
        .iter()
        .find(|o| o["disabled"] != Value::Bool(true))
        .ok_or_else(|| format!("Dialog {field_type} field requires at least one enabled option"))?;
    let default_text = opt_string(default_value);
    let selected = normalized.iter().find(|o| {
        default_text.as_deref() == o["value"].as_str() && o["disabled"] != Value::Bool(true)
    });
    let chosen = selected.unwrap_or(first_enabled)["value"]
        .as_str()
        .unwrap_or("")
        .to_string();
    Ok((normalized, chosen))
}

fn normalize_condition_value(value: &Value, context: &str) -> Result<Value, String> {
    match value {
        Value::String(_) | Value::Bool(_) => Ok(value.clone()),
        Value::Number(n) if n.as_f64().is_some_and(f64::is_finite) => Ok(value.clone()),
        _ => Err(format!("{context} must be a string, number, or boolean")),
    }
}

/// `normalizeDialogCondition`.
pub fn normalize_dialog_condition(condition: &Value, context: &str) -> Result<Value, String> {
    let Value::Object(map) = condition else {
        return Err(format!("{context} must be an object"));
    };
    let field = opt_string(map.get("field"))
        .unwrap_or_default()
        .trim()
        .to_string();
    if field.is_empty() {
        return Err(format!("{context} field is required"));
    }
    let operators: Vec<&str> = ["equals", "notEquals", "truthy", "falsy"]
        .into_iter()
        .filter(|op| map.contains_key(*op))
        .collect();
    if operators.len() != 1 {
        return Err(format!("{context} requires exactly one condition operator"));
    }
    let operator = operators[0];
    let mut out = Map::new();
    out.insert("field".into(), Value::String(field));
    if operator == "truthy" || operator == "falsy" {
        if map.get(operator) != Some(&Value::Bool(true)) {
            return Err(format!("{context} {operator} must be true"));
        }
        out.insert(operator.into(), Value::Bool(true));
        return Ok(Value::Object(out));
    }
    out.insert(
        operator.into(),
        normalize_condition_value(&map[operator], &format!("{context} {operator}"))?,
    );
    Ok(Value::Object(out))
}

fn matches_number_step(value: f64, step: f64, base: f64) -> bool {
    let quotient = (value - base) / step;
    (quotient - quotient.round()).abs() < 1e-9
}

/// `Number(x)` unless `x` is undefined / null / `""`.
fn optional_number(value: Option<&Value>) -> Result<Option<f64>, ()> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(v) => match js_number(v) {
            Some(n) if n.is_finite() => Ok(Some(n)),
            _ => Err(()),
        },
    }
}

fn number_json(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < i64::MAX as f64 {
        json!(n as i64)
    } else {
        json!(n)
    }
}

fn normalize_dialog_field(
    field: &Value,
    seen_names: &mut HashSet<String>,
) -> Result<Value, String> {
    let Value::Object(map) = field else {
        return Err("Dialog form field must be an object".into());
    };
    let field_type = opt_string(map.get("type")).unwrap_or_default();
    if !["select", "checkbox", "radio", "textarea", "number"].contains(&field_type.as_str()) {
        return Err(format!(
            "Unsupported dialog field type: {}",
            if field_type.is_empty() {
                "unknown"
            } else {
                &field_type
            }
        ));
    }
    let name = opt_string(map.get("name"))
        .unwrap_or_default()
        .trim()
        .to_string();
    if name.is_empty() {
        return Err("Dialog form field name is required".into());
    }
    if ["__proto__", "prototype", "constructor"].contains(&name.as_str()) {
        return Err(format!("Dialog form field name is reserved: {name}"));
    }
    if !seen_names.insert(name.clone()) {
        return Err(format!("Duplicate dialog form field name: {name}"));
    }

    let mut out = Map::new();
    out.insert("type".into(), Value::String(field_type.clone()));
    out.insert("name".into(), Value::String(name.clone()));
    out.insert(
        "label".into(),
        Value::String(opt_string(map.get("label")).unwrap_or_else(|| name.clone())),
    );
    if let Some(description) = opt_string(map.get("description")) {
        out.insert("description".into(), Value::String(description));
    }
    out.insert(
        "required".into(),
        Value::Bool(map.get("required") != Some(&Value::Bool(false))),
    );
    if !is_nullish(map.get("visibleWhen")) {
        out.insert(
            "visibleWhen".into(),
            normalize_dialog_condition(&map["visibleWhen"], "Dialog visibleWhen")?,
        );
    }

    match field_type.as_str() {
        "checkbox" => {
            out.insert(
                "required".into(),
                Value::Bool(map.get("required") == Some(&Value::Bool(true))),
            );
            out.insert(
                "defaultValue".into(),
                Value::Bool(map.get("defaultValue").is_some_and(js_truthy)),
            );
        }
        "textarea" => {
            if let Some(placeholder) = opt_string(map.get("placeholder")) {
                out.insert("placeholder".into(), Value::String(placeholder));
            }
            out.insert(
                "defaultValue".into(),
                Value::String(opt_string(map.get("defaultValue")).unwrap_or_default()),
            );
        }
        "number" => {
            let default_number = optional_number(map.get("defaultValue")).map_err(|_| {
                format!("Dialog number field defaultValue must be a finite number: {name}")
            })?;
            let min = optional_number(map.get("min"))
                .map_err(|_| format!("Dialog number field min must be a finite number: {name}"))?;
            let max = optional_number(map.get("max"))
                .map_err(|_| format!("Dialog number field max must be a finite number: {name}"))?;
            let step = optional_number(map.get("step")).map_err(|_| {
                format!("Dialog number field step must be a positive finite number: {name}")
            })?;
            if step.is_some_and(|s| s <= 0.0) {
                return Err(format!(
                    "Dialog number field step must be a positive finite number: {name}"
                ));
            }
            if let (Some(min), Some(max)) = (min, max) {
                if min > max {
                    return Err(format!(
                        "Dialog number field min cannot be greater than max: {name}"
                    ));
                }
            }
            if let (Some(d), Some(min)) = (default_number, min) {
                if d < min {
                    return Err(format!(
                        "Dialog number field defaultValue cannot be less than min: {name}"
                    ));
                }
            }
            if let (Some(d), Some(max)) = (default_number, max) {
                if d > max {
                    return Err(format!(
                        "Dialog number field defaultValue cannot be greater than max: {name}"
                    ));
                }
            }
            if let (Some(d), Some(step), Some(min)) = (default_number, step, min) {
                if !matches_number_step(d, step, min) {
                    return Err(format!(
                        "Dialog number field defaultValue must match step from min: {name}"
                    ));
                }
            }
            if let Some(placeholder) = opt_string(map.get("placeholder")) {
                out.insert("placeholder".into(), Value::String(placeholder));
            }
            if let Some(d) = default_number {
                out.insert("defaultValue".into(), number_json(d));
            }
            if let Some(min) = min {
                out.insert("min".into(), number_json(min));
            }
            if let Some(max) = max {
                out.insert("max".into(), number_json(max));
            }
            if let Some(step) = step {
                out.insert("step".into(), number_json(step));
            }
        }
        _ => {
            let (options, default_value) =
                normalize_choice_options(&field_type, map.get("options"), map.get("defaultValue"))?;
            out.insert("options".into(), Value::Array(options));
            out.insert("defaultValue".into(), Value::String(default_value));
        }
    }
    Ok(Value::Object(out))
}

/// `normalizeDialogFormSpec`: validate a `dialog.form` spec and return the
/// `ScriptDialogForm` the renderer receives.
pub fn normalize_dialog_form_spec(spec: &Value) -> Result<Value, String> {
    let Value::Object(map) = spec else {
        return Err("Dialog form spec must be an object".into());
    };
    let Some(Value::Array(raw_fields)) = map.get("fields") else {
        return Err("Dialog form requires at least one field".into());
    };
    if raw_fields.is_empty() {
        return Err("Dialog form requires at least one field".into());
    }
    let mut seen = HashSet::new();
    let fields: Vec<Value> = raw_fields
        .iter()
        .map(|f| normalize_dialog_field(f, &mut seen))
        .collect::<Result<_, _>>()?;
    let names: Vec<String> = fields
        .iter()
        .map(|f| f["name"].as_str().unwrap_or("").to_string())
        .collect();
    for (index, field) in fields.iter().enumerate() {
        let Some(condition) = field.get("visibleWhen") else {
            continue;
        };
        let target = condition["field"].as_str().unwrap_or("");
        if !seen.contains(target) {
            return Err(format!(
                "Dialog visibleWhen references unknown field: {target}"
            ));
        }
        if let Some(dependency) = names.iter().position(|n| n == target) {
            if dependency >= index {
                return Err(format!(
                    "Dialog visibleWhen must reference an earlier field: {}",
                    names[index]
                ));
            }
        }
    }
    let mut out = Map::new();
    if let Some(title) = opt_string(map.get("title")) {
        out.insert("title".into(), Value::String(title));
    }
    out.insert(
        "message".into(),
        Value::String(opt_string(map.get("message")).unwrap_or_default()),
    );
    if let Some(label) = opt_string(map.get("submitLabel")) {
        out.insert("submitLabel".into(), Value::String(label));
    }
    if let Some(label) = opt_string(map.get("cancelLabel")) {
        out.insert("cancelLabel".into(), Value::String(label));
    }
    out.insert("fields".into(), Value::Array(fields));
    Ok(Value::Object(out))
}

/// Value a cleared / abandoned dialog resolves with (`defaultDialogValue`).
pub fn default_dialog_value(dialog_type: &str) -> Value {
    match dialog_type {
        "confirm" => Value::Bool(false),
        "prompt" => Value::String(String::new()),
        "form" => Value::Object(Map::new()),
        "waitForTimeout" => Value::String("abort".into()),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_fields_and_default_choice_values() {
        let spec = json!({
            "title": "Deploy",
            "message": "Pick",
            "fields": [
                { "type": "select", "name": "env", "label": "Env", "options": ["dev", { "value": "prod", "label": "Prod", "disabled": true }], "defaultValue": "prod" },
                { "type": "radio", "name": "mode", "options": [{ "value": "a", "description": "A" }, "b"], "defaultValue": "b" },
                { "type": "checkbox", "name": "force", "defaultValue": "yes" },
                { "type": "textarea", "name": "notes", "placeholder": "..." , "required": false },
                { "type": "number", "name": "count", "defaultValue": "4", "min": 0, "max": 10, "step": 2, "visibleWhen": { "field": "force", "truthy": true } }
            ]
        });
        let form = normalize_dialog_form_spec(&spec).unwrap();
        assert_eq!(form["title"], "Deploy");
        assert_eq!(form["message"], "Pick");
        let fields = form["fields"].as_array().unwrap();
        // Disabled default falls back to the first enabled option.
        assert_eq!(fields[0]["defaultValue"], "dev");
        assert_eq!(fields[0]["options"][1]["disabled"], true);
        assert_eq!(fields[0]["required"], true);
        assert_eq!(fields[1]["defaultValue"], "b");
        assert_eq!(fields[1]["options"][0]["description"], "A");
        assert_eq!(fields[1]["label"], "mode");
        assert_eq!(fields[2]["defaultValue"], true);
        assert_eq!(fields[2]["required"], false);
        assert_eq!(fields[3]["defaultValue"], "");
        assert_eq!(fields[3]["required"], false);
        assert_eq!(fields[4]["defaultValue"], 4);
        assert_eq!(fields[4]["step"], 2);
        assert_eq!(
            fields[4]["visibleWhen"],
            json!({ "field": "force", "truthy": true })
        );
    }

    #[test]
    fn rejects_invalid_fields() {
        let cases: Vec<(Value, &str)> = vec![
            (json!(null), "Dialog form spec must be an object"),
            (
                json!({ "fields": [] }),
                "Dialog form requires at least one field",
            ),
            (
                json!({ "fields": [1] }),
                "Dialog form field must be an object",
            ),
            (
                json!({ "fields": [{ "type": "text", "name": "x" }] }),
                "Unsupported dialog field type: text",
            ),
            (
                json!({ "fields": [{ "type": "select" }] }),
                "Dialog form field name is required",
            ),
            (
                json!({ "fields": [{ "type": "select", "name": "__proto__" }] }),
                "Dialog form field name is reserved: __proto__",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a" }, { "type": "checkbox", "name": "a" }] }),
                "Duplicate dialog form field name: a",
            ),
            (
                json!({ "fields": [{ "type": "select", "name": "a", "options": [] }] }),
                "Dialog select field requires at least one option",
            ),
            (
                json!({ "fields": [{ "type": "select", "name": "a", "options": [""] }] }),
                "Dialog option value is required",
            ),
            (
                json!({ "fields": [{ "type": "select", "name": "a", "options": [1] }] }),
                "Dialog option must be a string or object",
            ),
            (
                json!({ "fields": [{ "type": "select", "name": "a", "options": ["x", "x"] }] }),
                "Dialog select field option values must be unique: x",
            ),
            (
                json!({ "fields": [{ "type": "radio", "name": "a", "options": [{ "value": "x", "disabled": true }] }] }),
                "Dialog radio field requires at least one enabled option",
            ),
            (
                json!({ "fields": [{ "type": "number", "name": "n", "defaultValue": "abc" }] }),
                "Dialog number field defaultValue must be a finite number: n",
            ),
            (
                json!({ "fields": [{ "type": "number", "name": "n", "step": 0 }] }),
                "Dialog number field step must be a positive finite number: n",
            ),
            (
                json!({ "fields": [{ "type": "number", "name": "n", "min": 5, "max": 1 }] }),
                "Dialog number field min cannot be greater than max: n",
            ),
            (
                json!({ "fields": [{ "type": "number", "name": "n", "min": 5, "defaultValue": 1 }] }),
                "Dialog number field defaultValue cannot be less than min: n",
            ),
            (
                json!({ "fields": [{ "type": "number", "name": "n", "max": 5, "defaultValue": 9 }] }),
                "Dialog number field defaultValue cannot be greater than max: n",
            ),
            (
                json!({ "fields": [{ "type": "number", "name": "n", "min": 0, "step": 2, "defaultValue": 3 }] }),
                "Dialog number field defaultValue must match step from min: n",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a", "visibleWhen": "x" }] }),
                "Dialog visibleWhen must be an object",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a", "visibleWhen": {} }] }),
                "Dialog visibleWhen field is required",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a", "visibleWhen": { "field": "b" } }] }),
                "Dialog visibleWhen requires exactly one condition operator",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a", "visibleWhen": { "field": "b", "truthy": false } }] }),
                "Dialog visibleWhen truthy must be true",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a", "visibleWhen": { "field": "b", "equals": {} } }] }),
                "Dialog visibleWhen equals must be a string, number, or boolean",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a", "visibleWhen": { "field": "zzz", "truthy": true } }] }),
                "Dialog visibleWhen references unknown field: zzz",
            ),
            (
                json!({ "fields": [{ "type": "checkbox", "name": "a", "visibleWhen": { "field": "b", "truthy": true } }, { "type": "checkbox", "name": "b" }] }),
                "Dialog visibleWhen must reference an earlier field: a",
            ),
        ];
        for (spec, expected) in cases {
            assert_eq!(
                normalize_dialog_form_spec(&spec).unwrap_err(),
                expected,
                "{spec}"
            );
        }
    }

    #[test]
    fn default_dialog_values() {
        assert_eq!(default_dialog_value("confirm"), json!(false));
        assert_eq!(default_dialog_value("prompt"), json!(""));
        assert_eq!(default_dialog_value("form"), json!({}));
        assert_eq!(default_dialog_value("waitForTimeout"), json!("abort"));
        assert_eq!(default_dialog_value("alert"), Value::Null);
    }
}
