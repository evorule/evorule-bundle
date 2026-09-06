//! 规则体结构门禁（轻量版）——SSOT：evorule-system-rules `_shared`/`rule_set` v1.0。
//!
//! 治理侧（evorule-rule 入口）与执行侧（evorule-server）共用，把"是否可执行"从运行时
//! 问题提前到构建期/治理期。拦截 P0-01 主错误：
//! - 非法元指令类型（不在 6 元指令白名单）→ 防止指令层类型混入元指令层；
//! - 单数 `__io_result__`（引擎写复数 `__io_results__`）→ 防止运行时 PathResolutionFailed；
//! - 路径语法错误（空段 / 非法索引 / 非法字符）。
//!
//! 边界：本门禁是**轻量**实现，非逐字节 jsonschema（完整 schema 校验由执行侧
//! `evorule-rule-schema` 承担）。残余窗口："治理侧放行、执行侧完整 schema 拒收"。
//!
//! 许可：Apache-2.0（自 v0.2.1 起；历史版本曾以 AGPL-3.0-or-later 发布）

use serde_json::Value;

/// 6 元指令白名单（SSOT：`evorule-tcb/src/executor.rs` dispatch ↔ `_shared/v1.0.json` enum）
pub const META_INSTRUCTION_TYPES: [&str; 6] =
    ["set", "push", "branch", "io_request", "collect", "merge"];

/// 校验规则体结构。支持 `{"transform": [...]}` 或裸 transform 数组。
/// 失败时返回错误列表（非空），成功返回 `Ok(())`。
pub fn validate_rule_structure(input: &Value) -> Result<(), Vec<String>> {
    let transform: &Vec<Value> = if let Some(t) = input.get("transform").and_then(Value::as_array) {
        t
    } else if let Some(t) = input.as_array() {
        t
    } else {
        return Err(vec![
            "rule_body 必须是 transform 数组或含 transform 字段的对象".to_string(),
        ]);
    };

    if transform.is_empty() {
        return Err(vec!["transform 数组不能为空".to_string()]);
    }

    let mut errors = Vec::new();
    for (i, step) in transform.iter().enumerate() {
        match step.get("type").and_then(Value::as_str) {
            Some(ty) if META_INSTRUCTION_TYPES.contains(&ty) => {}
            Some(ty) => errors.push(format!(
                "transform[{i}].type='{ty}' 不是元指令（白名单: {}）",
                META_INSTRUCTION_TYPES.join("/")
            )),
            None => errors.push(format!("transform[{i}] 缺 type")),
        }
        scan_strings(step, i, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// 递归扫描节点内所有字符串值：
/// - 单数 `__io_result__` 检查对所有字符串值生效（不区分字段，防拼写错误）；
/// - 路径语法检查**仅限路径语义字段**（attr/path/args/service_name），
///   避免把自由文本（如 LLM prompt/system 消息中的 `xxx.json`）误判为路径。
fn scan_strings(node: &Value, idx: usize, errors: &mut Vec<String>) {
    scan_strings_field(node, idx, errors, false);
}

/// `is_path_field`：当前字段是否为路径语义字段（决定是否做路径语法检查）。
/// 嵌套对象/数组会递归，路径语义由各层字段名重新判定。
fn scan_strings_field(node: &Value, idx: usize, errors: &mut Vec<String>, is_path_field: bool) {
    match node {
        Value::String(s) => {
            check_singular_io_result(s, idx, errors);
            if is_path_field {
                check_path_string(s, idx, errors);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                scan_strings_field(v, idx, errors, is_path_field);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let nested = matches!(k.as_str(), "attr" | "path" | "args" | "service_name");
                scan_strings_field(v, idx, errors, nested);
            }
        }
        _ => {}
    }
}

fn check_singular_io_result(s: &str, idx: usize, errors: &mut Vec<String>) {
    // 单数 __io_result__ 强制拒绝（引擎写复数 __io_results__）
    if s.contains("__io_result__") {
        errors.push(format!(
            "transform[{idx}] 引用单数 '__io_result__'，必须用复数 '__io_results__'"
        ));
    }
}

fn check_path_string(s: &str, idx: usize, errors: &mut Vec<String>) {
    // 仅对"形如路径"的字符串做语法检查（含 . 或 [ 或 __ 前缀）
    let looks_path = s.contains('.') || s.contains('[') || s.starts_with("__");
    if looks_path && !valid_path_syntax(s) {
        errors.push(format!("transform[{idx}] 路径语法非法: '{s}'"));
    }
}

/// 路径语法校验（对齐 `_shared/v1.0.json` path pattern + Opt1 负向清单）：
/// 合法段字符 `[A-Za-z0-9_$\-\\]`，段间用 `.` 或 `.[N]` 或尾随 `[N]` 索引。
fn valid_path_syntax(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let cs: Vec<char> = s.chars().collect();
    let n = cs.len();
    let mut i = 0;

    while i < n {
        // 解析一段：连续段字符
        let seg_start = i;
        while i < n && is_seg_char(cs[i]) {
            i += 1;
        }
        if i == seg_start {
            return false; // 空段 / 非法开头（如 .x、[0、[]、[abc]）
        }
        // 可选索引 [N]
        if i < n && cs[i] == '[' {
            i += 1;
            let mut j = i;
            while j < n && cs[j].is_ascii_digit() {
                j += 1;
            }
            if j == i || j >= n || cs[j] != ']' {
                return false; // [] / [abc] / [0（未闭合）
            }
            i = j + 1;
        }
        if i == n {
            break;
        }
        // 段间分隔：'.'（后跟段字符或 [N]）
        if cs[i] == '.' {
            i += 1;
            if i >= n {
                return false; // 尾部空段 x.
            }
            if cs[i] == '[' {
                // data.[0] 合法：解析 [N]
                i += 1;
                let mut j = i;
                while j < n && cs[j].is_ascii_digit() {
                    j += 1;
                }
                if j == i || j >= n || cs[j] != ']' {
                    return false;
                }
                i = j + 1;
                continue;
            }
            if !is_seg_char(cs[i]) {
                return false; // x..y（双点）或 . 后非法字符
            }
            continue;
        }
        return false; // 其他字符（空白 / [0]abc / 非法符号）
    }
    true
}

fn is_seg_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '\\' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(v: Value) -> bool {
        validate_rule_structure(&v).is_ok()
    }

    #[test]
    fn 合法_transform_数组_通过() {
        let v = json!({
            "transform": [
                {"type": "branch", "params": {
                    "domain": {"type": "instruction", "instruction_type": "compute_ik"},
                    "on_true": [],
                    "on_false": []
                }},
                {"type": "set", "params": {"attr": "a.b", "operation": "set", "value": 1}}
            ]
        });
        assert!(ok(v));
    }

    #[test]
    fn 裸数组_通过() {
        let v = json!([
            {"type": "set", "params": {"attr": "a", "operation": "set", "value": 1}}
        ]);
        assert!(ok(v));
    }

    #[test]
    fn 非数组或对象_拒绝() {
        assert!(!ok(json!(123)));
        assert!(!ok(json!("x")));
        assert!(!ok(json!(null)));
    }

    #[test]
    fn 空transform_拒绝() {
        assert!(!ok(json!({"transform": []})));
    }

    #[test]
    fn 非法元指令_拒绝() {
        let v = json!({"transform": [{"type": "increment", "params": {"attr": "x"}}]});
        assert!(!ok(v));
        let v2 = json!({"transform": [{"type": "save_memory", "params": {}}]});
        assert!(!ok(v2));
    }

    #[test]
    fn 单数io_result_拒绝() {
        let v = json!({"transform": [{"type": "branch", "params": {
            "domain": {"type": "exists", "path": "__exec__.payload.__io_result__"},
            "on_true": []}}]});
        assert!(!ok(v));
    }

    #[test]
    fn 复数io_results_通过() {
        let v = json!({"transform": [{"type": "branch", "params": {
            "domain": {"type": "exists", "path": "__exec__.payload.__io_results__.call_service"},
            "on_true": []}}]});
        assert!(ok(v));
    }

    #[test]
    fn 路径语法负向_拒绝() {
        // 仅"形如路径"的字符串（含 . 或 [ 或 __ 前缀）受轻量门禁检查
        for bad in [
            "x.",
            ".x",
            "x..y",
            "items[0]..name",
            "[0",
            "[]",
            "[abc]",
            "[0]abc",
        ] {
            let v = json!({"transform": [{"type": "set", "params": {"attr": bad, "operation": "set", "value": 1}}]});
            assert!(!ok(v), "应拒绝路径: {bad}");
        }
    }

    #[test]
    fn 非路径纯值_轻量门禁放行() {
        // 残余窗口：非路径形字符串（如普通文本值）由完整 jsonschema（执行侧）把关，
        // 轻量门禁不误伤（"foo bar" 作为 set.value 合法）
        let v = json!({"transform": [{"type": "set", "params": {"attr": "a.b", "operation": "set", "value": "foo bar"}}]});
        assert!(ok(v));
    }

    #[test]
    fn 自由文本含点_放行() {
        // LLM prompt/system 消息中的文本含 `core_eval.json` 的点，但语义非路径 → 放行
        let v = json!({"transform": [{"type": "set", "params": {
            "attr": "_patch_args.system", "operation": "set",
            "value": "你生成的规则必须严格遵守core_eval.json规范，且只能针对参数阈值进行调整。"}
        }]});
        assert!(ok(v), "含点的自由文本不应被误判为非法路径");
    }

    #[test]
    fn 自由文本含单数io_result_仍拒绝() {
        // 单数 __io_result__ 检查不区分字段：即使出现在 value 自由文本中也拒绝
        let v = json!({"transform": [{"type": "set", "params": {
            "attr": "a", "operation": "set",
            "value": "引用 __io_result__ 的说明文本" }
        }]});
        assert!(!ok(v));
    }

    #[test]
    fn 路径语法正向_通过() {
        for good in [
            "__exec__.payload.$schema",
            "data[0]",
            "data.[0]",
            "payload.a.b[2].c",
            "__exec__.payload.__io_results__.call_service",
        ] {
            let v = json!({"transform": [{"type": "set", "params": {"attr": good, "operation": "set", "value": 1}}]});
            assert!(ok(v), "应通过路径: {good}");
        }
    }
}
