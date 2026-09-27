//! 规则体结构门禁（轻量版）——SSOT：evorule-system-rules `_shared`/`rule_set` v1.0。
//!
//! 治理侧（evorule-rule 入口）与执行侧（evorule-server）共用，把"是否可执行"从运行时
//! 问题提前到构建期/治理期。拦截 P0-01 主错误：
//! - 非法元指令类型（不在元指令白名单，5 种）→ 防止指令层类型混入元指令层；
//! - 单数 `__io_result__`（引擎写复数 `__io_results__`）→ 防止运行时 PathResolutionFailed；
//! - 路径语法错误（空段 / 非法索引 / 非法字符）。
//! - **结构级**：params 必须存在且为对象、条目级键白名单 {type,params}、各类型关键
//!   子字段（set.attr/operation、push.instructions、branch.domain/on_true、
//!   io_request.io_type）存在性+类型校验（2026-09-26 补缺：堵 PowerShell 深度截断
//!   导致的 params 类型污染等"治理放行、执行拒收"窗口；对齐 `_shared` transform_rule
//!   $defs 的结构级约束，语义深校验仍归执行侧）。
//!
//! 边界：本门禁是**轻量**实现，非逐字节 jsonschema（完整 schema 校验由执行侧
//! `evorule-rule-schema` 承担）。残余窗口已收窄为纯语义级（如 set.value 缺省、
//! domain 求值类型），结构级不再有放行窗口。
//!
//! 许可：AGPL-3.0-or-later（自 v0.3.1 起；历史版本曾以 Apache-2.0（v0.2.1–v0.3.0）与 AGPL-3.0-or-later（≤ v0.2.0）发布，crates.io 已发布版本许可不可改，消费方钉版时注意许可口径）

use serde_json::Value;

/// 元指令白名单（SSOT：`evorule-tcb/src/executor.rs` dispatch ↔ `_shared/v1.0.json` enum；
/// 对齐闸：evorule-system-rules `tools/check_whitelist_sync.py` 第四向校验，2026-09-15 接入）。
/// 规则清理批次（v0.6.0）collect/merge 退役；enforce 属元指令第五种（tier=meta 语义，
/// 由 server 装载门禁管控其进入，本门禁只管"是否元指令形态"）。
pub const META_INSTRUCTION_TYPES: [&str; 5] = ["branch", "set", "push", "io_request", "enforce"];

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
        validate_transform_step(step, &format!("transform[{i}]"), &mut errors);
        scan_strings(step, i, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// 单步元指令结构校验（轻量，对齐 `_shared/v1.0.json` transform_rule $defs 的结构级约束；
/// 完整逐字节 jsonschema 仍由执行侧 evorule-rule-schema 承担——本函数只堵"结构级"残余窗口：
/// params 类型污染 / 条目级未知键 / 各类型关键子字段缺失或类型错）。
/// 字符串级检查（单数 __io_result__ / 路径语法）由主循环的 scan_strings 递归覆盖，此处不重复。
///
/// `path` 为错误定位描述（如 "transform[0].params.on_true[1]"）；`errors` 收集错误。
fn validate_transform_step(step: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(map) = step.as_object() else {
        errors.push(format!("{path} 必须是对象"));
        return;
    };
    // 条目级键白名单（对齐 additionalProperties:false）：防 LLM 转写把匹配条件写成
    // 条目级 condition 等未知键导致引擎静默忽略（意图静默丢失防御，_shared 注释同源）
    for key in map.keys() {
        if key != "type" && key != "params" {
            errors.push(format!(
                "{path} 未知条目级键 '{key}'（仅允许 type/params；条件语义必须经 params 内的 domain/enforce 原语表达）"
            ));
        }
    }
    // params 必须存在且为对象（required: [type, params]；堵 ConvertTo-Json 深度截断等
    // 将 params 整体污染为字符串/数组的入库窗口）
    let params = match step.get("params") {
        Some(Value::Object(p)) => p,
        Some(_) => {
            errors.push(format!("{path}.params 必须是对象（当前为非对象值）"));
            return;
        }
        None => {
            errors.push(format!("{path} 缺 params（元指令条目必填 type+params）"));
            return;
        }
    };
    let ty = match step.get("type").and_then(Value::as_str) {
        Some(t) if META_INSTRUCTION_TYPES.contains(&t) => t,
        Some(t) => {
            errors.push(format!(
                "{path}.type='{t}' 不是元指令（白名单: {}）",
                META_INSTRUCTION_TYPES.join("/")
            ));
            return;
        }
        None => {
            errors.push(format!("{path} 缺 type"));
            return;
        }
    };
    // 按类型做关键子结构存在性+类型校验（轻量；语义深校验归执行侧）
    match ty {
        "set" => {
            check_params_field(
                params,
                path,
                "attr",
                errors,
                Value::is_string,
                "attr 必须是字符串路径",
            );
            check_params_field(
                params,
                path,
                "operation",
                errors,
                Value::is_string,
                "operation 必须是字符串",
            );
        }
        "push" => match params.get("instructions") {
            Some(Value::Array(arr)) => {
                for (j, ins) in arr.iter().enumerate() {
                    validate_instruction_ref(
                        ins,
                        &format!("{path}.params.instructions[{j}]"),
                        errors,
                    );
                }
            }
            Some(Value::String(s)) if s.starts_with("__") => {}
            Some(_) => errors.push(format!(
                "{path}.params.instructions 必须是指令数组或 __ 前缀路径字符串"
            )),
            None => errors.push(format!("{path}.params.instructions 缺失（push 必填）")),
        },
        "branch" => {
            if params.get("domain").is_none() {
                errors.push(format!("{path}.params.domain 缺失（branch 必填）"));
            }
            match params.get("on_true") {
                Some(Value::Array(arr)) => {
                    for (j, sub) in arr.iter().enumerate() {
                        validate_transform_step(
                            sub,
                            &format!("{path}.params.on_true[{j}]"),
                            errors,
                        );
                    }
                }
                Some(_) => errors.push(format!("{path}.params.on_true 必须是数组")),
                None => errors.push(format!("{path}.params.on_true 缺失（branch 必填）")),
            }
            if let Some(v) = params.get("on_false") {
                match v {
                    Value::Array(arr) => {
                        for (j, sub) in arr.iter().enumerate() {
                            validate_transform_step(
                                sub,
                                &format!("{path}.params.on_false[{j}]"),
                                errors,
                            );
                        }
                    }
                    _ => errors.push(format!("{path}.params.on_false 必须是数组")),
                }
            }
        }
        "io_request" => {
            check_params_field(
                params,
                path,
                "io_type",
                errors,
                Value::is_string,
                "io_type 必须是字符串",
            );
        }
        // enforce：形态校验（tier=meta 进入管控由 server 装载门禁承担，回归验证）
        _ => {}
    }
}

/// 校验 params 内某字段的存在性+类型谓词。
fn check_params_field(
    params: &serde_json::Map<String, Value>,
    path: &str,
    field: &str,
    errors: &mut Vec<String>,
    pred: fn(&Value) -> bool,
    msg: &str,
) {
    match params.get(field) {
        Some(v) if pred(v) => {}
        Some(_) => errors.push(format!("{path}.params.{field} {msg}（当前为非预期类型）")),
        None => errors.push(format!("{path}.params.{field} 缺失（{field} 必填）")),
    }
}

/// 指令层引用校验（push.instructions 元素）：object 须含 string type 且 params 若存在须为
/// object；string 须 __ 前缀路径。指令层 type 任意（core_eval 匹配的 instruction_type，
/// 含 increment/decrement/sequence 等），不做元指令白名单。
fn validate_instruction_ref(ins: &Value, path: &str, errors: &mut Vec<String>) {
    match ins {
        Value::Object(map) => {
            match map.get("type").and_then(Value::as_str) {
                Some(_) => {}
                None => errors.push(format!("{path} 指令缺 type")),
            }
            if let Some(p) = map.get("params") {
                if !p.is_object() {
                    errors.push(format!("{path}.params 必须是对象"));
                }
            }
        }
        Value::String(s) => {
            if !s.starts_with("__") {
                errors.push(format!("{path} 字符串指令引用必须 __ 前缀（当前: '{s}'）"));
            }
        }
        _ => errors.push(format!("{path} 指令项必须是对象或 __ 前缀字符串")),
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
    fn collect_merge_已退役_拒绝() {
        // 规则清理批次（v0.6.0）collect/merge 退役；bundle 侧白名单 2026-09-15 同步收窄
        for ty in ["collect", "merge"] {
            let v = json!({"transform": [{"type": ty, "params": {}}]});
            assert!(!ok(v), "{ty} 已退役，应拒绝");
        }
    }

    #[test]
    fn enforce_元指令_形态通过() {
        // enforce 为元指令第五种（SSOT = TCB dispatch 全量）；tier=meta 进入管控属
        // server 装载门禁（回归验证），本轻量门禁只校验形态
        let v = json!({"transform": [{"type": "enforce", "params": {}}]});
        assert!(ok(v));
    }

    #[test]
    fn 白名单_ssot_快照() {
        // 对齐闸的仓内锚点：TCB dispatch 变更时本测试先红（check_whitelist_sync.py
        // 为跨仓权威校验，此处快照防仓内无声漂移）
        assert_eq!(
            META_INSTRUCTION_TYPES,
            ["branch", "set", "push", "io_request", "enforce"]
        );
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

    // ===== 2026-09-26 补缺：结构级门禁（params 类型污染 / 条目级未知键 / 子字段缺失）=====

    #[test]
    fn params_非对象_拒绝() {
        // PowerShell ConvertTo-Json 深度截断污染形态（P0 实测 H1 根因）：params 整体变成字符串
        let v = json!([{"type": "push", "params": "@{instructions=System.Object[]}"}]);
        assert!(!ok(v), "params 字符串污染应拒绝");
        let v2 = json!([{"type": "set", "params": [1, 2, 3]}]);
        assert!(!ok(v2), "params 数组应拒绝");
    }

    #[test]
    fn 缺params_拒绝() {
        let v = json!([{"type": "set"}]);
        assert!(!ok(v));
    }

    #[test]
    fn 条目级未知键_拒绝() {
        // LLM 转写把匹配条件写成条目级 condition → 引擎静默忽略（意图静默丢失防御）
        let v = json!([{"type": "set", "params": {"attr": "a", "operation": "set", "value": 1}, "condition": {"type": "eq"}}]);
        assert!(!ok(v), "条目级 condition 应拒绝");
    }

    #[test]
    fn set_缺attr_operation_拒绝() {
        let v = json!([{"type": "set", "params": {"value": 1}}]);
        assert!(!ok(v), "set 缺 attr/operation 应拒绝");
    }

    #[test]
    fn push_instructions_污染_拒绝() {
        // instructions 被字符串化（非 __ 前缀字符串）
        let v = json!([{"type": "push", "params": {"instructions": "@{System.Object[]}"}}]);
        assert!(!ok(v), "instructions 非 __ 前缀字符串应拒绝");
        let v2 = json!([{"type": "push", "params": {}}]);
        assert!(!ok(v2), "push 缺 instructions 应拒绝");
    }

    #[test]
    fn branch_缺domain_or_on_true_拒绝() {
        let v = json!([{"type": "branch", "params": {"on_true": []}}]);
        assert!(!ok(v), "branch 缺 domain 应拒绝");
        let v2 = json!([{"type": "branch", "params": {"domain": {"type": "exists", "path": "a.b"}}}]);
        assert!(!ok(v2), "branch 缺 on_true 应拒绝");
    }

    #[test]
    fn io_request_缺io_type_拒绝() {
        let v = json!([{"type": "io_request", "params": {"service_name": "x"}}]);
        assert!(!ok(v), "io_request 缺 io_type 应拒绝");
    }

    #[test]
    fn push_指令层_宽松通过() {
        // 指令层 type 任意（increment/sequence 等），不做元指令白名单；params 可选 object
        let v = json!([{"type": "push", "params": {
            "instructions": [
                {"type": "increment", "params": {"attr": "count", "delta": 1}},
                {"type": "sequence", "params": {"instructions": [{"type": "set", "params": {"attr": "x", "operation": "set", "value": 1}}]}}
            ]
        }}]);
        assert!(ok(v));
        // __ 前缀路径引用
        let v2 = json!([{"type": "push", "params": {"instructions": "__exec__.instruction.params.then"}}]);
        assert!(ok(v2));
    }

    #[test]
    fn branch_递归子结构校验() {
        // on_true 递归 transform_rule：子步骤缺 params 应被递归拦截
        let v = json!([{"type": "branch", "params": {
            "domain": {"type": "exists", "path": "a.b"},
            "on_true": [{"type": "set", "params": {"value": 1}}]
        }}]);
        assert!(!ok(v), "branch.on_true 子步骤缺 attr/operation 应被递归拒绝");
    }
}
