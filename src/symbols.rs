//! 符号提取（31 号 §9-3）：从 rule_body 提取 io_request.service_name 符号集
//!
//! 纯函数，不依赖治理侧 schema / RuleDataset / RuleEntry —— 快照包自洽校验所需。
//! SSOT：本函数唯一来源在 evorule-bundle，evorule-rule 的 `Validator::io_services_from_rule_body`
//! 改为调用本函数（re-export），避免两份定义漂移。

use serde_json::Value;

/// 判断 service_name 是否为动态引用（运行时从 `__exec__.instruction.params.*` 解析）。
///
/// 动态引用 = 以 `__` 系统前缀开头或含 `.` 的路径串（非字面量服务名，如
/// `__exec__.instruction.params.service_name` / `__exec__.instruction.params.sampling_service`）。
fn is_dynamic_service_ref(name: &str) -> bool {
    name.starts_with("__") || name.contains('.')
}

/// 递归收集 rule_body 中所有 `type=io_request` 步骤的 `params.service_name`。
///
/// 递归遍历所有 JSON 节点（branch/嵌套数组均可），保证嵌套规则体（如
/// `branch → branch → io_request` 的 yuanze 形态）的符号能被提取：
/// - 非动态 service_name（字面量）→ 入 `out`；
/// - 动态引用（`__exec__.instruction.params.*`）→ 置 `has_dynamic=true`，不入 `out`。
fn collect_io_services(value: &Value, out: &mut Vec<String>, has_dynamic: &mut bool) {
    match value {
        Value::Object(obj) => {
            if obj.get("type").and_then(|t| t.as_str()) == Some("io_request") {
                if let Some(name) = obj
                    .get("params")
                    .and_then(|p| p.get("service_name"))
                    .and_then(|s| s.as_str())
                {
                    if is_dynamic_service_ref(name) {
                        *has_dynamic = true;
                    } else {
                        out.push(name.to_string());
                    }
                }
            }
            for v in obj.values() {
                collect_io_services(v, out, has_dynamic);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_io_services(v, out, has_dynamic);
            }
        }
        _ => {}
    }
}

/// 从 rule_body 提取所有 `type=io_request` 步骤的 `params.service_name` 字面量。
///
/// - 结构无法解析 → 返回空集（不 panic）；
/// - 递归扫描（branch 嵌套的 io_request 同样提取）；
/// - **动态 service_name（`__exec__.instruction.params.*`）不入字面量列表**（运行时解析，
///   由 `has_dynamic_service_ref` 单独标注，调用方决定是否豁免 body 匹配）；
/// - 空集可能意味着"无外部数据依赖"（规则体自洽），由调用方结合 binding 判断。
pub fn io_services_from_rule_body(rule_body: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut has_dynamic = false;
    collect_io_services(rule_body, &mut out, &mut has_dynamic);
    out
}

/// 规则体是否含动态 service 引用（`__exec__.instruction.params.*`）。
///
/// 用于 bundle 符号一致性校验：含动态引用时，dependencies 的 service_name 跳过 body 字面量
/// 匹配（依赖声明仍为权威，须 ∈ data_dependencies）。递归扫描（branch 嵌套同样识别）。
pub fn has_dynamic_service_ref(rule_body: &Value) -> bool {
    let mut out = Vec::new();
    let mut has_dynamic = false;
    collect_io_services(rule_body, &mut out, &mut has_dynamic);
    has_dynamic
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extracts_io_services() {
        let body = json!({
            "rule_id": "r1",
            "transform": [
                { "type": "io_request", "params": { "service_name": "payroll_svc" } },
                { "type": "set", "params": { "path": "a", "value": 1 } }
            ]
        });
        assert_eq!(io_services_from_rule_body(&body), vec!["payroll_svc"]);
    }

    #[test]
    fn test_empty_when_no_io_or_bad_structure() {
        assert!(io_services_from_rule_body(&json!({"rule_id": "r1"})).is_empty());
        assert!(io_services_from_rule_body(&json!({"transform": []})).is_empty());
        // io_request 缺 service_name → 跳过
        let body = json!({
            "transform": [ { "type": "io_request", "params": {} } ]
        });
        assert!(io_services_from_rule_body(&body).is_empty());
    }

    #[test]
    fn test_dynamic_service_ref_excluded_from_literals() {
        // 动态 service_name（__exec__.instruction.params.*）不入字面量列表
        let body = json!({
            "rule_id": "r1",
            "transform": [
                { "type": "io_request", "params": { "service_name": "__exec__.instruction.params.service_name" } },
                { "type": "io_request", "params": { "service_name": "payroll_svc" } }
            ]
        });
        assert_eq!(io_services_from_rule_body(&body), vec!["payroll_svc"]);
    }

    #[test]
    fn test_has_dynamic_service_ref() {
        let dyn_body = json!({
            "transform": [
                { "type": "io_request", "params": { "service_name": "__exec__.instruction.params.sampling_service" } }
            ]
        });
        assert!(has_dynamic_service_ref(&dyn_body));

        let literal_body = json!({
            "transform": [
                { "type": "io_request", "params": { "service_name": "robot_move_service" } }
            ]
        });
        assert!(!has_dynamic_service_ref(&literal_body));

        assert!(!has_dynamic_service_ref(&json!({"rule_id": "r1"})));
        assert!(!has_dynamic_service_ref(&json!({"transform": []})));
    }

    #[test]
    fn test_extracts_nested_io_services_in_branch() {
        // yuanze 形态：branch → branch → io_request（递归提取嵌套符号）
        let body = json!({
            "transform": [
                {
                    "type": "branch",
                    "params": {
                        "domain": { "type": "instruction", "instruction_type": "audit_alert" },
                        "on_true": [
                            {
                                "type": "branch",
                                "params": {
                                    "domain": { "type": "exists", "path": "__exec__.payload.__io_results__.call_service" },
                                    "on_false": [
                                        { "type": "set", "params": { "attr": "_llm_args.model", "operation": "set", "value": "gpt" } },
                                        {
                                            "type": "io_request",
                                            "params": { "io_type": "call_service", "service_name": "llm_advisor", "args": "__exec__.payload._llm_args" }
                                        }
                                    ],
                                    "on_true": []
                                }
                            }
                        ]
                    }
                }
            ]
        });
        let services = io_services_from_rule_body(&body);
        assert_eq!(services, vec!["llm_advisor"]);
        assert!(!has_dynamic_service_ref(&body));
    }

    #[test]
    fn test_extracts_nested_dynamic_and_literal_mixed() {
        // 同一嵌套规则体：动态引用标记 + 字面量入列表
        let body = json!({
            "transform": [
                {
                    "type": "branch",
                    "params": {
                        "domain": { "type": "instruction", "instruction_type": "compute_ik" },
                        "on_true": [
                            {
                                "type": "branch",
                                "params": {
                                    "domain": { "type": "exists", "path": "__exec__.payload.__io_results__.call_service" },
                                    "on_false": [
                                        {
                                            "type": "io_request",
                                            "params": { "io_type": "call_service", "service_name": "__exec__.instruction.params.service_name", "args": "__exec__.payload._ik_args" }
                                        }
                                    ],
                                    "on_true": [
                                        {
                                            "type": "io_request",
                                            "params": { "io_type": "call_service", "service_name": "shadow_ik_solver", "args": "__exec__.payload.service_result" }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        });
        let services = io_services_from_rule_body(&body);
        assert_eq!(services, vec!["shadow_ik_solver"]);
        assert!(has_dynamic_service_ref(&body));
    }
}
