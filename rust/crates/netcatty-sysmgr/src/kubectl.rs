//! Background kubectl queries (Electron `systemManager/kubectlOps.cjs`):
//! contexts, namespaces, pods and pod deletion for the Kubernetes tab.

use crate::container_runtime::{
    build_kubectl_contexts_command, build_kubectl_delete_pod_command,
    build_kubectl_namespaces_command, build_kubectl_pods_command, is_kubectl_unreachable_error,
    js_string, js_truthy, parse_kubeconfig_contexts, parse_kubectl_pod_list, parse_namespace_list,
    KubectlShell,
};
use crate::exec::{now_ms, ExecRequest, ExecResult, LocalPlatform, SessionExec};
use serde_json::{json, Value};

/// Electron `failureResult`: unreachable-cluster spam becomes a stable
/// `clusterUnreachable` code, anything else the trimmed stderr / error.
fn failure_result(result: &ExecResult, fallback: &str) -> Value {
    let raw = result.command_error(fallback);
    if is_kubectl_unreachable_error(&raw) {
        return json!({ "success": false, "errorCode": "clusterUnreachable" });
    }
    json!({ "success": false, "error": raw })
}

/// `String(value ?? "")` for an optional payload field.
fn arg(payload: &Value, key: &str) -> String {
    match payload.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    }
}

/// Namespace argument: present only when not null / empty.
fn namespace_arg(payload: &Value) -> Option<String> {
    match payload.get("namespace") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(v) => Some(js_string(v)),
    }
}

/// Run one kubectl op. Payload: `{ sessionId, op, context?, namespace?, pod? }`
/// (the renderer's `shell` is ignored: background commands are quoted for
/// the executor — PowerShell for local Windows sessions, POSIX otherwise).
pub async fn run(exec: &dyn SessionExec, payload: &Value) -> Value {
    let session_id = payload.get("sessionId").filter(|v| js_truthy(v));
    let op = payload.get("op").filter(|v| js_truthy(v));
    let (Some(_), Some(op)) = (session_id, op) else {
        return json!({ "success": false, "error": "Missing params" });
    };
    let op = js_string(op);

    if op == "contexts" {
        let result = exec
            .exec(ExecRequest::new(build_kubectl_contexts_command(), 10_000))
            .await;
        if !result.is_successful() {
            return failure_result(&result, "kubectl exited");
        }
        return match parse_kubeconfig_contexts(&result.stdout) {
            Some((contexts, current)) => json!({
                "success": true,
                "contexts": contexts
                    .into_iter()
                    .map(|c| json!({ "name": c.name, "namespace": c.namespace, "current": c.current }))
                    .collect::<Vec<_>>(),
                "current": current,
            }),
            None => json!({ "success": false, "error": "Failed to parse Kubernetes contexts" }),
        };
    }

    let shell = if exec.is_local() && exec.local_platform() == LocalPlatform::Win32 {
        KubectlShell::PowerShell
    } else {
        KubectlShell::Posix
    };
    let context = arg(payload, "context");
    let namespace = namespace_arg(payload);

    match op.as_str() {
        "namespaces" => {
            let Some(command) = build_kubectl_namespaces_command(&context, shell) else {
                return json!({ "success": false, "error": "Invalid context" });
            };
            let result = exec.exec(ExecRequest::new(command, 12_000)).await;
            if !result.is_successful() {
                return failure_result(&result, "kubectl exited");
            }
            match parse_namespace_list(&result.stdout) {
                Some(namespaces) => json!({ "success": true, "namespaces": namespaces }),
                None => {
                    json!({ "success": false, "error": "Failed to parse Kubernetes namespaces" })
                }
            }
        }
        "pods" => {
            let Some(command) = build_kubectl_pods_command(&context, namespace.as_deref(), shell)
            else {
                return json!({ "success": false, "error": "Invalid context or namespace" });
            };
            let result = exec.exec(ExecRequest::new(command, 15_000)).await;
            if !result.is_successful() {
                return failure_result(&result, "kubectl exited");
            }
            match parse_kubectl_pod_list(&result.stdout, now_ms()) {
                Some(pods) => json!({ "success": true, "pods": pods }),
                None => json!({ "success": false, "error": "Failed to parse Kubernetes pods" }),
            }
        }
        "delete" => {
            let pod = arg(payload, "pod");
            let Some(command) =
                build_kubectl_delete_pod_command(&context, namespace.as_deref(), &pod, shell)
            else {
                return json!({ "success": false, "error": "Invalid pod" });
            };
            let result = exec.exec(ExecRequest::new(command, 20_000)).await;
            if !result.is_successful() {
                return failure_result(&result, "kubectl delete failed");
            }
            json!({ "success": true })
        }
        other => json!({ "success": false, "error": format!("Invalid kubectl op: {other}") }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeExec;

    fn items_ok() -> ExecResult {
        ExecResult::ok("{\"items\":[]}", "", 0)
    }

    #[tokio::test]
    async fn local_windows_quotes_for_the_executor_not_cmd() {
        let fake = FakeExec::new(|_, _| items_ok()).local(LocalPlatform::Win32);
        let result = run(
            &fake,
            &json!({ "sessionId": "local-cmd", "op": "namespaces", "context": "prod-$east", "shell": "cmd" }),
        )
        .await;
        assert_eq!(result["success"], true);
        run(
            &fake,
            &json!({
                "sessionId": "local-cmd", "op": "delete", "context": "prod-$east",
                "namespace": "kube-system", "pod": "coredns-$east", "shell": "cmd"
            }),
        )
        .await;
        let commands = fake.commands();
        assert!(commands[0].contains("--context 'prod-$east'"));
        assert!(!commands[0].contains('"'));
        assert!(commands[1].contains("--context 'prod-$east'"));
        assert!(commands[1].contains("-n 'kube-system'"));
        assert!(commands[1].contains("delete pod 'coredns-$east'"));
        assert!(!commands[1].contains('"'));
        // Executor runs through the session, not exec_local.
        assert!(!fake.requests()[0].1);
    }

    #[tokio::test]
    async fn remote_session_stays_posix_even_when_payload_asks_for_cmd() {
        let fake = FakeExec::new(|_, _| items_ok());
        run(
            &fake,
            &json!({ "sessionId": "ssh", "op": "pods", "context": "o'brien", "namespace": "default", "shell": "cmd" }),
        )
        .await;
        let command = &fake.commands()[0];
        assert!(command.contains("--context 'o'\"'\"'brien'"));
        assert!(!command.contains("--context \"o'brien\""));
        assert_eq!(fake.requests()[0].0.timeout_ms, 15_000);
    }

    #[tokio::test]
    async fn unreachable_api_becomes_stable_code() {
        let stderr = "memcache.go:381] \"Couldn't get current server API group list\"\nGet \"https://127.0.0.1:6443/api?timeout=32s\": dial tcp 127.0.0.1:6443: connect: connection refused";
        let fake = FakeExec::new(move |_, _| ExecResult::ok("", stderr, 1));
        let result = run(
            &fake,
            &json!({ "sessionId": "s1", "op": "pods", "context": "broken-cluster", "namespace": "default" }),
        )
        .await;
        assert_eq!(
            result,
            json!({ "success": false, "errorCode": "clusterUnreachable" })
        );
    }

    #[tokio::test]
    async fn namespaces_keep_forbidden_text() {
        let fake = FakeExec::new(|_, _| {
            ExecResult::ok(
                "",
                "Error from server (Forbidden): namespaces is forbidden: User \"view\" cannot list resource \"namespaces\"",
                1,
            )
        });
        let result = run(
            &fake,
            &json!({ "sessionId": "s1", "op": "namespaces", "context": "prod" }),
        )
        .await;
        assert_eq!(result["success"], false);
        assert!(result.get("errorCode").is_none());
        assert!(result["error"].as_str().unwrap().contains("Forbidden"));
    }

    #[tokio::test]
    async fn contexts_parse_and_validation_errors() {
        let fake = FakeExec::new(|_, _| {
            ExecResult::ok(
                "{\"current-context\":\"a\",\"contexts\":[{\"name\":\"a\",\"context\":{}}]}",
                "",
                0,
            )
        });
        let result = run(&fake, &json!({ "sessionId": "s1", "op": "contexts" })).await;
        assert_eq!(
            result,
            json!({
                "success": true,
                "contexts": [{ "name": "a", "namespace": "default", "current": true }],
                "current": "a"
            })
        );
        assert_eq!(fake.commands()[0], "kubectl config view -o json");

        assert_eq!(
            run(&fake, &json!({ "op": "pods" })).await,
            json!({ "success": false, "error": "Missing params" })
        );
        assert_eq!(
            run(&fake, &json!({ "sessionId": "s1", "op": "namespaces" })).await,
            json!({ "success": false, "error": "Invalid context" })
        );
        assert_eq!(
            run(
                &fake,
                &json!({ "sessionId": "s1", "op": "delete", "context": "c" })
            )
            .await,
            json!({ "success": false, "error": "Invalid pod" })
        );
        assert_eq!(
            run(&fake, &json!({ "sessionId": "s1", "op": "nope" })).await,
            json!({ "success": false, "error": "Invalid kubectl op: nope" })
        );

        let bad = FakeExec::new(|_, _| ExecResult::ok("garbage", "", 0));
        assert_eq!(
            run(&bad, &json!({ "sessionId": "s1", "op": "contexts" })).await,
            json!({ "success": false, "error": "Failed to parse Kubernetes contexts" })
        );
        let failed = FakeExec::new(|_, _| ExecResult::ok("", "", 1));
        assert_eq!(
            run(
                &failed,
                &json!({ "sessionId": "s1", "op": "delete", "context": "c", "pod": "p" })
            )
            .await,
            json!({ "success": false, "error": "kubectl delete failed" })
        );
    }
}
