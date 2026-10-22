//! Fixed public IPC failures. Internal diagnostics may retain redacted context;
//! user-controlled paths/config/log excerpts never become a public error DTO.
use super::*;
#[derive(Clone, Copy)]
pub(crate) enum RuntimeCommand {
    Connect,
    Disconnect,
    Proxy,
    Rollback,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeFailure {
    code: &'static str,
    category: &'static str,
    retryable: bool,
}
pub(crate) fn contextual_runtime_error(error: &str, context: &str) -> String {
    // Keep the leading machine code through internal context wrappers. Only
    // the fixed NativeFailure whitelist is allowed across the IPC boundary.
    format!("{error}: {context}")
}
impl NativeFailure {
    pub(crate) fn task_failed() -> Self {
        Self {
            code: "RUNTIME_COMMAND_TASK_FAILED",
            category: "lifecycle",
            retryable: false,
        }
    }
    pub(crate) fn from_error(message: &str, command: RuntimeCommand) -> Self {
        let token = message
            .split([':', ' ', '\r', '\n'])
            .next()
            .unwrap_or_default();
        let code = match token {
            "RUNTIME_BUSY" => "RUNTIME_BUSY",
            "RUNTIME_SUPERSEDED" => "RUNTIME_SUPERSEDED",
            "OPERATION_CANCELLED" => "OPERATION_CANCELLED",
            "OPERATION_DEADLINE" => "OPERATION_DEADLINE",
            "STATE_CLOSING" => "STATE_CLOSING",
            "PROCESS_STOP_UNCONFIRMED" => "PROCESS_STOP_UNCONFIRMED",
            "CLEANUP_INCOMPLETE" => "RUNTIME_CLEANUP_INCOMPLETE",
            "NETWORK_MODE_INVALID" => "NETWORK_MODE_INVALID",
            "NETWORK_IP_STACK_INVALID" => "NETWORK_IP_STACK_INVALID",
            "NETWORK_BINDING_CHANGED" => "NETWORK_BINDING_CHANGED",
            "NETWORK_BINDING_UNCONFIRMED" => "NETWORK_BINDING_UNCONFIRMED",
            "ROUTE_INTERFACE_CHANGED" => "ROUTE_INTERFACE_CHANGED",
            "ROUTE_INTERFACE_UNAVAILABLE" => "ROUTE_INTERFACE_UNAVAILABLE",
            "ROUTE_JOURNAL_UNAVAILABLE" => "ROUTE_JOURNAL_UNAVAILABLE",
            "TUN_INTERFACE_NOT_READY" => "TUN_INTERFACE_NOT_READY",
            "TUN_ROUTES_UNCONFIRMED" => "TUN_ROUTES_UNCONFIRMED",
            "SESSION_UNAUTHORIZED" => "SESSION_UNAUTHORIZED",
            "SESSION_CHANGED" => "SESSION_CHANGED",
            "SUBSCRIPTION_UNAVAILABLE" => "SUBSCRIPTION_UNAVAILABLE",
            "SUBSCRIPTION_REJECTED" => "SUBSCRIPTION_REJECTED",
            "CORE_PORT_CONFLICT" => "CORE_PORT_CONFLICT",
            "CORE_PORT_TIMEOUT" => "CORE_PORT_TIMEOUT",
            "CORE_EXITED_EARLY" => "CORE_EXITED_EARLY",
            "CORE_NOT_FOUND" => "CORE_NOT_FOUND",
            "TUN_ELEVATION_REQUIRED" => "TUN_ELEVATION_REQUIRED",
            "TUN_IPV6_UNSUPPORTED" => "TUN_IPV6_UNSUPPORTED",
            "TUN_PROCESS_ENFORCEMENT_UNAVAILABLE" => "TUN_PROCESS_ENFORCEMENT_UNAVAILABLE",
            "REQUEST_IDENTITY" => "REQUEST_IDENTITY",
            "CONNECT_PREFLIGHT" => "CONNECT_PREFLIGHT",
            "PROXY_OWNER_CHANGED" => "PROXY_OWNER_CHANGED",
            "ROUTE_OWNER_CHANGED" => "ROUTE_OWNER_CHANGED",
            "CONFIG_PROVENANCE_MISSING" => "CONFIG_PROVENANCE_MISSING",
            _ => match command {
                RuntimeCommand::Connect => "RUNTIME_CONNECT_FAILED",
                RuntimeCommand::Disconnect => "RUNTIME_DISCONNECT_FAILED",
                RuntimeCommand::Proxy => "RUNTIME_PROXY_FAILED",
                RuntimeCommand::Rollback => "RUNTIME_ROLLBACK_FAILED",
            },
        };
        Self {
            code,
            category: if matches!(code, "TUN_ELEVATION_REQUIRED") {
                "permission"
            } else {
                "network"
            },
            retryable: matches!(code, "RUNTIME_BUSY" | "CORE_PORT_TIMEOUT"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_cleanup_stays_explicit_and_never_exports_internal_detail() {
        for command in [
            RuntimeCommand::Connect,
            RuntimeCommand::Disconnect,
            RuntimeCommand::Rollback,
        ] {
            let value = serde_json::to_value(NativeFailure::from_error(
                "CLEANUP_INCOMPLETE: PRIVATE-DETAIL",
                command,
            ))
            .unwrap();
            assert_eq!(value["code"], "RUNTIME_CLEANUP_INCOMPLETE");
            assert_eq!(value["retryable"], false);
            assert_eq!(value.as_object().unwrap().len(), 3);
            assert!(!value.to_string().contains("PRIVATE"));
        }
    }
    #[test]
    fn route_context_keeps_the_root_code_but_cannot_promote_a_nested_untrusted_code() {
        for (root, expected) in [
            ("ROUTE_JOURNAL_UNAVAILABLE", "ROUTE_JOURNAL_UNAVAILABLE"),
            ("OPERATION_CANCELLED: PRIVATE-DETAIL", "OPERATION_CANCELLED"),
            (
                "unknown: ROUTE_JOURNAL_UNAVAILABLE",
                "RUNTIME_CONNECT_FAILED",
            ),
        ] {
            let error = contextual_runtime_error(root, "PRIVATE-CONTEXT");
            let value =
                serde_json::to_value(NativeFailure::from_error(&error, RuntimeCommand::Connect))
                    .unwrap();
            assert_eq!(value["code"], expected);
            assert!(!value.to_string().contains("PRIVATE"));
            assert_eq!(value.as_object().unwrap().len(), 3);
        }
    }
    #[test]
    fn error_dto_never_exports_internal_paths_urls_log_excerpts_or_localized_messages() {
        for text in [
            "CORE_PORT_TIMEOUT: private C:/fixture secret log",
            "https://sub.vkarmani.com/private",
            "RUNTIME_FUTURE_SECRET: token",
            "Runtime уже выполняет другое действие",
            "",
        ] {
            let v = serde_json::to_value(NativeFailure::from_error(text, RuntimeCommand::Connect))
                .unwrap();
            assert_eq!(v.as_object().unwrap().len(), 3);
            assert!(!v.to_string().contains("private"));
            assert!(!v.to_string().contains("secret"));
            assert!(!v.to_string().contains("Runtime уже"));
        }
        assert_eq!(
            serde_json::to_value(NativeFailure::from_error(
                "CORE_PORT_TIMEOUT: context",
                RuntimeCommand::Connect
            ))
            .unwrap()["code"],
            "CORE_PORT_TIMEOUT"
        );
    }
    #[test]
    fn failure_classification_uses_only_allowlisted_machine_tokens_and_preserves_cancellation() {
        for (input, code) in [
            ("OPERATION_CANCELLED: anything", "OPERATION_CANCELLED"),
            ("RUNTIME_SUPERSEDED: anything", "RUNTIME_SUPERSEDED"),
            ("RUNTIME_BUSY: anything", "RUNTIME_BUSY"),
            ("TUN_ELEVATION_REQUIRED", "TUN_ELEVATION_REQUIRED"),
            ("arbitrary port operation string", "RUNTIME_CONNECT_FAILED"),
        ] {
            assert_eq!(
                serde_json::to_value(NativeFailure::from_error(input, RuntimeCommand::Connect))
                    .unwrap()["code"],
                code
            );
        }
        assert_eq!(
            serde_json::to_value(NativeFailure::from_error(
                "unknown",
                RuntimeCommand::Disconnect
            ))
            .unwrap()["code"],
            "RUNTIME_DISCONNECT_FAILED"
        );
        assert_eq!(
            serde_json::to_value(NativeFailure::from_error(
                "unknown",
                RuntimeCommand::Rollback
            ))
            .unwrap()["retryable"],
            false
        );
    }
}
