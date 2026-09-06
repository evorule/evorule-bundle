//! 数据依赖声明（31 号 §6；完整设计在 35 号 决策点⑤）
//!
//! - 数据集级 `data_dependencies`：声明规则运行所需数据来源（推入式 inputs / 拉取式 services）；
//! - 条目级 `data_source_binding`：将 `rule_body` 内的 service_name 符号映射到具体服务；
//! - 凭据强约束：声明不存端点/凭据（凭据永不入库，只走执行侧密钥管理）。
//!
//! 符号三方一致（31 号 §9-3）：
//! `rule_body.io_request.service_name` ≡ 条目 binding.service_name ≡ 数据集声明 services[].service_name
//!
//! SSOT：依赖模型唯一来源在本 crate（evorule-bundle），evorule-rule 侧 re-export。
//! 治理专属的 `ServiceTemplateRecord`（44 号 §7 deps/templates 注册）留在 evorule-rule。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 推入式输入声明（事件/Fact 形态，供沙箱生成合成事件；35 号 §4 完整 schema）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputDecl {
    pub name: String,
    /// 输入形态 schema（JSON Schema 子集）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 事件长期为空是否视为异常（35 号 §4，默认 false；开放点② 建议 false）
    #[serde(default)]
    pub empty_allowed: bool,
}

/// 事件方向（段B B5：MVP 恒为 push；预留扩展位避免未来破坏性 schema 升级）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventDirection {
    /// 推入式：外部系统向规则引擎推事件（数据集声明事件形态契约）
    #[default]
    Push,
}

/// 数据集级 push 事件 schema 声明（段B B5，14 号）
///
/// - 声明数据集消费的推入式事件的**形态契约**（name + schema_ref + direction），
///   供消费方做契约发现；回写事件（RuleFailureEvent）定型不变，与此声明无关；
/// - `schema_ref` 指向领域 JSON Schema（领域仓资产），导入侧经
///   [`crate::bundle::DomainSchemaResolver`] 门禁强校验（fail-fast，未注册即拒绝）；
/// - 事件名数据集内唯一（重名显式拒绝，不静默覆盖）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventSchemaDecl {
    /// 事件名（数据集内唯一；与 InputDecl.name 同一命名空间语义）
    pub name: String,
    /// 领域 JSON Schema 引用 URI（与 KnowledgeEntry.schema_ref 同一解析器体系）
    pub schema_ref: String,
    /// 方向（MVP 恒为 push）
    #[serde(default)]
    pub direction: EventDirection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// 无凭据服务模板（35 号 §5，决策点⑤ 方案 B）
///
/// 模板 = 端点形状 + 参数占位 + 说明，**不含真实端点/密钥**；实际值由消费者在
/// 执行侧 service_registry 填写（层 2 绑定动作，§3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceTemplate {
    /// 允许占位符（如 "https://{base}/api/payroll"），实际值由消费者填
    pub url: String,
    /// 默认 POST（35 号 §3）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// 鉴权头模板（占位符形式，如 `{client_id}`）；BTreeMap 保证序列化确定性（36 号内容哈希）
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers_templates: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms_hint: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// 拉取式服务声明
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceDecl {
    pub service_name: String,
    /// 服务业务版本（C4：版本语义与规则版本对齐；来自服务目录 SSOT）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 输入输出契约
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_contract: Option<IoContract>,
    /// 是否涉及凭据/敏感数据
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 无凭据服务模板（可选，帮助消费者配置；35 号 §5）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<ServiceTemplate>,
}

/// 服务输入输出契约
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct IoContract {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#in: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out: Option<Value>,
}

/// 数据集级数据依赖声明
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DataDependencies {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<InputDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceDecl>,
}

impl DataDependencies {
    /// 是否声明了指定服务
    pub fn has_service(&self, service_name: &str) -> bool {
        self.services.iter().any(|s| s.service_name == service_name)
    }
}

/// 条目级绑定：rule_body 内符号 → 具体服务（rule_ref 记录符号在 rule_body 中的路径）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceBinding {
    pub rule_ref: String,
    pub service_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_dependencies_serde() {
        let dd = DataDependencies {
            inputs: vec![InputDecl {
                name: "payroll_event".into(),
                schema: Some(serde_json::json!({"emp_id": "string"})),
                description: Some("工资计算触发事件".into()),
                empty_allowed: false,
            }],
            services: vec![ServiceDecl {
                service_name: "payroll_svc".into(),
                version: Some("1.2.0".into()),
                io_contract: Some(IoContract {
                    r#in: Some(serde_json::json!({"emp_id": "string"})),
                    out: Some(serde_json::json!({"amount": "number"})),
                }),
                sensitive: false,
                description: Some("工资发放数据服务".into()),
                template: Some(ServiceTemplate {
                    url: "https://{base}/api/payroll".into(),
                    method: Some("POST".into()),
                    headers_templates: BTreeMap::from([(
                        "X-Client-Id".into(),
                        "{client_id}".into(),
                    )]),
                    timeout_ms_hint: Some(5000),
                    notes: Some("base/鉴权按客户环境填写".into()),
                }),
            }],
        };
        let json = serde_json::to_string(&dd).unwrap();
        assert!(json.contains("payroll_svc"));
        assert!(json.contains("{client_id}")); // 模板占位符保留
        let back: DataDependencies = serde_json::from_str(&json).unwrap();
        assert_eq!(dd, back);
        assert!(back.has_service("payroll_svc"));
        assert!(!back.has_service("nope"));
        assert_eq!(back.services[0].version.as_deref(), Some("1.2.0"));
        // 缺省字段回退（老数据兼容：无 template/description/empty_allowed/version 反序列化成功）
        let old: DataDependencies =
            serde_json::from_str(r#"{"services":[{"service_name":"s","sensitive":false}]}"#)
                .unwrap();
        assert_eq!(old.services[0].template, None);
        assert_eq!(old.services[0].description, None);
        assert_eq!(old.services[0].version, None);
        assert_eq!(old.inputs, vec![]);
    }

    #[test]
    fn test_event_schema_decl_serde() {
        let decl = EventSchemaDecl {
            name: "payroll_event".into(),
            schema_ref: "https://rpsm.evorule.org/schemas/payroll-event/v1.0.json".into(),
            direction: EventDirection::Push,
            description: Some("工资发放触发事件".into()),
        };
        let json = serde_json::to_string(&decl).unwrap();
        assert!(json.contains("\"direction\":\"push\""));
        let back: EventSchemaDecl = serde_json::from_str(&json).unwrap();
        assert_eq!(decl, back);
        // 缺省兼容：无 direction/description 字段（老格式/手写 JSON）→ push + None
        let old: EventSchemaDecl =
            serde_json::from_str(r#"{"name":"e","schema_ref":"https://x/s.json"}"#).unwrap();
        assert_eq!(old.direction, EventDirection::Push);
        assert_eq!(old.description, None);
    }
}
