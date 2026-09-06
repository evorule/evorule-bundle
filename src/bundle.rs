//! 快照包消费层（决策点⑥ · 36 号）：类型 + 导入校验 + 裁剪
//!
//! - **DatasetBundle（快照包）**：资产 ↔ 执行解耦的唯一传输形态（单文件 JSON），只读产物；
//! - **导入校验**（evorule-server 侧前置）：schema → 防篡改 → 符号三方一致 → 版本解析 → 闸门一证据；
//!   落 workspace 与热加载属执行侧（27 号真热加载），本层返回校验通过的运行配置；
//! - **裁剪**（服务公司）：裁剪 = 原版本视图，**不新造版本链**（决策点②），依赖声明随裁剪收缩；
//! - **回写通道 MVP 不实现**：只定 schema（36 号 §6），不实现采集与闭环。
//!
//! 零转译：`entries[].rule_body` 原样 = evorule-server 可执行规则 JSON。
//!
//! **导出（BundleExporter）依赖治理侧 RuleDataset/RuleEntry，留在 evorule-rule**（T1 决策）——
//! 本 crate 只承载快照包自洽校验（类型 + BundleImporter + BundleTrimmer）。
//!
//! SSOT：快照包类型与校验唯一来源在本 crate（evorule-bundle），evorule-rule 侧 re-export。

use std::collections::HashSet;
use std::fmt;

use evorule_hash;
use jsonschema::{Draft, Validator};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dependency::{DataDependencies, EventSchemaDecl, SourceBinding};
use crate::provenance::Provenance;
use crate::resolve::{ResolveError, VersionResolver};
use crate::structure::validate_rule_structure;
use crate::symbols::{has_dynamic_service_ref, io_services_from_rule_body};
use crate::version::{LawRef, VersionError, VersionSelection, VersionSelectionMode, Versioning};

/// 当前支持的快照包 schema 版本
pub const BUNDLE_SCHEMA_VERSION: &str = "1.0";

/// 快照包错误（36 号 §3：失败显式报错，不静默降级）
#[derive(Debug, Error, PartialEq)]
pub enum BundleError {
    #[error("不支持的快照包 schema 版本 `{found}`（当前支持 {BUNDLE_SCHEMA_VERSION}）")]
    UnsupportedSchema { found: String },

    #[error("内容哈希不匹配：包内 `{recorded}` ≠ 实际 `{actual}`（包可能被篡改）")]
    ContentHashMismatch { recorded: String, actual: String },

    #[error("绑定服务 `{service}` 未在数据集 data_dependencies.services 中声明")]
    ServiceNotDeclared { service: String },

    #[error("绑定服务 `{service}` 未在 rule_body 的 io_request 中出现（规则体无此符号引用）")]
    ServiceNotInRuleBody { service: String },

    #[error("条目 `{entry}` rule_body 结构非法（引擎原生 transform 形态）: {errors:?}")]
    InvalidEntryStructure { entry: String, errors: Vec<String> },

    #[error(
        "知识数据条目 `{entry}` 缺少 schema_ref（D3 强校验：无领域 schema 的 payload 不得入库）"
    )]
    KnowledgeMissingSchemaRef { entry: String },

    #[error("条目 `{entry}` 的 schema_ref `{uri}` 未在解析器注册（fail-fast，不静默放行）")]
    SchemaNotResolved { entry: String, uri: String },

    #[error("条目 `{entry}` payload 未通过领域 schema `{uri}` 校验: {errors:?}")]
    PayloadSchemaViolation {
        entry: String,
        uri: String,
        errors: Vec<String>,
    },

    #[error("知识数据条目 `{entry}` 携带服务依赖（MVP 不支持：数据条目不经 io_request 消费服务，服务依赖属规则条目语义）")]
    KnowledgeWithDependencies { entry: String },

    #[error(
        "push 事件声明 `{name}` 的 schema_ref 为空（D3 强校验：无领域 schema 的事件声明不得入包）"
    )]
    EventSchemaMissingRef { name: String },

    #[error(
        "push 事件声明 `{name}` 的 schema_ref `{uri}` 未在解析器注册（fail-fast，不静默放行）"
    )]
    EventSchemaNotResolved { name: String, uri: String },

    #[error("push 事件声明 `{name}` 的领域 schema `{uri}` 本身非法: {errors:?}")]
    EventSchemaInvalid {
        name: String,
        uri: String,
        errors: Vec<String>,
    },

    #[error("push 事件声明 `{name}` 重复（数据集内事件名必须唯一）")]
    EventSchemaDuplicate { name: String },

    #[error("auto_by_effective_date 模式需快照包携带 law_ref.effective_from 作为生效基准")]
    MissingEffectiveBase,

    #[error("沙箱验证未通过（tests.verdict={verdict:?}），拒绝导入（闸门一证据）")]
    TestsNotPassed { verdict: TestVerdict },

    #[error("裁剪结果为空（所选条件无匹配条目）")]
    EmptyView,

    #[error("查询表达式段 `{0}` 非法（合法段：tag:x / domain:x / ids:a,b / kind:rule|knowledge / q:子串，多段以 ; 分隔）")]
    BadFilterSegment(String),

    #[error("版本解析错误: {0}")]
    Resolve(#[from] ResolveError),

    #[error("版本错误: {0}")]
    Version(#[from] VersionError),
}

/// 沙箱验证结果（闸门一证据，决策点④）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TestVerdict {
    #[default]
    Pass,
    Fail,
}

impl fmt::Display for TestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestVerdict::Pass => write!(f, "pass"),
            TestVerdict::Fail => write!(f, "fail"),
        }
    }
}

/// 测试证据（36 号 §2：测试用例 + 沙箱验证结果随包携带，导入侧可复核）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BundleTests {
    /// 测试用例引用
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subset: Vec<String>,
    /// 夹具引用
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixtures: Vec<String>,
    /// 沙箱验证结果（pass 才能导入）
    #[serde(default)]
    pub verdict: TestVerdict,
}

impl BundleTests {
    /// 显式"未验证"证据（verdict=fail）：未跑真实沙箱验证的导出**不得默认 Pass**（T0 决策）。
    /// 供执行侧拉取 / 预览导出使用——调用方跑完测试工作台后应构造 `BundleTests { verdict: Pass, .. }` 走带证据导出。
    pub fn unverified() -> Self {
        Self {
            verdict: TestVerdict::Fail,
            ..Default::default()
        }
    }
}

/// 裁剪视图引用（36 号 §5：不新造版本链，指向原版本）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewRef {
    pub original_dataset_id: String,
    /// 被引用的原版本（= 导出时的 source_version）
    pub view_of_version: String,
}

/// 快照包数据集元数据（36 号 §2 dataset 段）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleDatasetMeta {
    pub dataset_id: String,
    pub name: String,
    pub tenant_id: String,
    /// 真实发布者身份（白标不掩盖，决策点⑨）
    pub instance_id: String,
    pub versioning: Versioning,
    /// 内嵌版本选择配置（决策点③），导入侧合并为运行配置
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_selection: Option<VersionSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law_ref: Option<LawRef>,
    /// 裁剪视图引用（非裁剪包为 None）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_of: Option<ViewRef>,
    /// 数据集级 push 事件 schema 声明（段B B5；随包携带供消费方契约发现）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_schemas: Vec<EventSchemaDecl>,
}

/// 条目类型（Q12 数据资产化：规则条目与数据条目正式分流，治理链共用）
///
/// - `Rule`（默认）：`rule_body` = 引擎原生 transform 指令集 → 进 TCB 确定性执行；
/// - `Knowledge`：`rule_body` = 领域结构化 payload（零转译）+ `schema_ref` 领域 schema 引用
///   → 不进 TCB，供领域服务经 io_request/service_registry 通道消费。
///
/// serde default = `Rule`：旧格式 bundle（无 entry_kind 字段）反序列化仍为规则条目，向后兼容。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    #[default]
    Rule,
    Knowledge,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryKind::Rule => write!(f, "rule"),
            EntryKind::Knowledge => write!(f, "knowledge"),
        }
    }
}

/// 领域 schema 解析器：按 `schema_ref` URI 返回领域 JSON Schema（领域仓资产）。
///
/// 返回 `None` = 该 URI 未注册 → 门禁拒绝（fail-fast，不静默放行）。
/// 宿主仓注入实现（bundle 保持通用，不内置任何领域）：
/// 治理侧（evorule-rule）与执行侧（evorule-server）各自持有一致的注册表。
pub type DomainSchemaResolver<'a> = &'a dyn Fn(&str) -> Option<serde_json::Value>;

/// 快照包条目（36 号 §2 entries 段，rule_body 原生 JSON）
///
/// 字段名 `rule_body` 保留（已在 crates.io 发布 0.2.x，字段名变更破坏哈希字节兼容）：
/// Knowledge 条目时该字段承载领域 payload，语义为"零转译条目体"，见 [`EntryKind`]。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleEntry {
    pub entry_id: String,
    /// 条目类型（缺省 = Rule，旧格式兼容）
    #[serde(default)]
    pub entry_kind: EntryKind,
    /// evorule 原生 JSON，零转译（Rule：transform 指令集；Knowledge：领域 payload）
    pub rule_body: serde_json::Value,
    /// Knowledge 条目必填：领域 JSON Schema 引用 URI（领域仓资产，D3 强校验）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    /// 溯源不丢出处
    pub provenance: Provenance,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// 条目级依赖（裁剪后收缩；Knowledge 条目 MVP 不支持）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<SourceBinding>,
}

/// 导出审计（36 号 §2 audit 段）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleAudit {
    pub exported_at: String,
    pub exported_by: String,
    /// 导出时的数据集版本（= 发布单位，决策点②）
    pub source_version: String,
    /// 全包哈希（blake3，防篡改）；前缀 `blake3:` 自描述算法
    #[serde(default)]
    pub content_hash: String,
    /// 内容哈希算法声明（当前恒为 blake3）。预留未来算法协商位，避免 schema 版本破坏性升级。
    #[serde(default = "default_hash_algo")]
    pub hash_algo: String,
}

/// `BundleAudit.hash_algo` 的默认值（单一算法阶段恒为 blake3）
fn default_hash_algo() -> String {
    "blake3".to_string()
}

/// 快照包（单文件 JSON，36 号 §2）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetBundle {
    /// 快照包自身版本（演进用）
    pub bundle_schema_version: String,
    pub bundle_id: String,
    pub dataset: BundleDatasetMeta,
    pub entries: Vec<BundleEntry>,
    /// 完整数据依赖声明（决策点⑤；裁剪视图收缩）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dependencies: Option<DataDependencies>,
    pub tests: BundleTests,
    pub audit: BundleAudit,
}

impl DatasetBundle {
    /// 全包内容哈希（blake3:hex）：对排除 `audit.content_hash` 本身的规范化 JSON 计算。
    /// 序列化字段顺序固定（struct 声明序）+ Value 键有序（serde_json 默认 BTreeMap）→ 确定性。
    /// 算法统一为 BLAKE3（blake3 crate），与 evorule-reactor 审计链同源，跨仓字节一致。
    pub fn compute_content_hash(&self) -> String {
        let mut canonical = self.clone();
        canonical.audit.content_hash.clear();
        evorule_hash::prefixed(&evorule_hash::json_digest(&canonical))
    }

    /// 防篡改校验：包内记录的哈希与实际重算是否一致
    pub fn verify_content_hash(&self) -> Result<(), BundleError> {
        let actual = self.compute_content_hash();
        if self.audit.content_hash == actual {
            Ok(())
        } else {
            Err(BundleError::ContentHashMismatch {
                recorded: self.audit.content_hash.clone(),
                actual,
            })
        }
    }
}

/// 导入校验结果（36 号 §3：校验通过后的运行配置；落 workspace 与热加载在执行侧）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub bundle_id: String,
    pub dataset_id: String,
    pub source_version: String,
    pub selection_mode: VersionSelectionMode,
    /// pinned 已解析出版本；auto 为运行时按事件日期解析（None，33 号）
    pub resolved_version: Option<String>,
    pub entry_count: usize,
    pub verdict: TestVerdict,
}

/// 导入校验（执行侧前置，36 号 §3 流程 1-4 + 闸门一证据）
pub struct BundleImporter;

impl BundleImporter {
    pub fn validate(
        bundle: &DatasetBundle,
        schema_resolver: DomainSchemaResolver<'_>,
    ) -> Result<ImportResult, BundleError> {
        // 1 schema 校验
        if bundle.bundle_schema_version != BUNDLE_SCHEMA_VERSION {
            return Err(BundleError::UnsupportedSchema {
                found: bundle.bundle_schema_version.clone(),
            });
        }
        // 2 防篡改（全包哈希）
        bundle.verify_content_hash()?;
        // 3 版本链完整性（防损坏版本链被导入）
        bundle.dataset.versioning.validate()?;
        // 4 符号三方一致 + 条目结构（SSOT: validate_entry，治理侧入库门禁同口径）
        let declared: Vec<String> = bundle
            .data_dependencies
            .as_ref()
            .map(|d| d.services.iter().map(|s| s.service_name.clone()).collect())
            .unwrap_or_default();
        for entry in &bundle.entries {
            Self::validate_entry(entry, &declared, schema_resolver)?;
        }
        // 4b push 事件声明门禁（段B B5）：事件名唯一 + schema_ref 经 resolver 强校验（fail-fast）
        Self::validate_event_schemas(&bundle.dataset.event_schemas, schema_resolver)?;
        // 5 版本解析（内嵌 version_selection 合并为运行配置；不可解析 → 显式错误）
        let chain = &bundle.dataset.versioning.chain;
        let selection = bundle.dataset.version_selection.as_ref();
        let mode = selection
            .map(|s| s.mode)
            .unwrap_or(VersionSelectionMode::AutoByEffectiveDate);
        let resolved_version = match selection {
            Some(sel) if sel.mode == VersionSelectionMode::Pinned => {
                Some(VersionResolver::resolve_pinned(sel, chain)?)
            }
            _ => {
                // auto：运行时按事件日期解析（33 号）；导入侧校验生效基准存在
                if bundle
                    .dataset
                    .law_ref
                    .as_ref()
                    .and_then(|l| l.effective_from.as_ref())
                    .is_none()
                {
                    return Err(BundleError::MissingEffectiveBase);
                }
                None
            }
        };
        // 6 闸门一证据：verdict=pass 才能导入（不静默降级）
        if bundle.tests.verdict != TestVerdict::Pass {
            return Err(BundleError::TestsNotPassed {
                verdict: bundle.tests.verdict,
            });
        }
        Ok(ImportResult {
            bundle_id: bundle.bundle_id.clone(),
            dataset_id: bundle.dataset.dataset_id.clone(),
            source_version: bundle.audit.source_version.clone(),
            selection_mode: mode,
            resolved_version,
            entry_count: bundle.entries.len(),
            verdict: bundle.tests.verdict,
        })
    }

    /// 条目级门禁（SSOT）：治理侧入库（evorule-rule `add_entry`）与执行侧导入（`validate`）
    /// 共用的拒绝口径——消除"治理放行、执行拒收"窗口。
    ///
    /// **按条目类型分流**（Q12 数据资产化，D1）：
    ///
    /// - `Rule` 条目：1) rule_body 结构（引擎原生 transform 形态，防 loader fail-soft 静默跳过
    ///   非法规则）；2) 符号三方一致（31 号 §9-3）：dependencies 必须在数据集服务声明中，且在
    ///   rule_body 有 io_request 引用。动态 service 引用（`__exec__.instruction.params.*`）
    ///   运行时解析，body 字面量不参与匹配。**transform 白名单不开洞**（TCB dispatch 唯一权威）。
    /// - `Knowledge` 条目：不做 transform 校验（数据条目不进 TCB）；改为 D3 强校验——
    ///   schema_ref 必填 + resolver 必须命中 + payload 过领域 jsonschema 校验；任一失败显式拒绝。
    ///   服务依赖 MVP 不支持（数据条目不经 io_request 消费服务），携带即拒绝。
    ///
    /// `declared_services`：数据集 data_dependencies.services 的服务名列表。
    /// `schema_resolver`：领域 schema 解析器（见 [`DomainSchemaResolver`]）。
    pub fn validate_entry(
        entry: &BundleEntry,
        declared_services: &[String],
        schema_resolver: DomainSchemaResolver<'_>,
    ) -> Result<(), BundleError> {
        match entry.entry_kind {
            EntryKind::Rule => Self::validate_rule_entry(entry, declared_services),
            EntryKind::Knowledge => Self::validate_knowledge_entry(entry, schema_resolver),
        }
    }

    /// Rule 条目门禁（transform 结构 + 符号三方一致，原 SSOT 口径一字不动）
    fn validate_rule_entry(
        entry: &BundleEntry,
        declared_services: &[String],
    ) -> Result<(), BundleError> {
        // 1) rule_body 结构
        validate_rule_structure(&entry.rule_body).map_err(|errors| {
            BundleError::InvalidEntryStructure {
                entry: entry.entry_id.clone(),
                errors,
            }
        })?;
        // 2) 符号三方一致
        let has_dynamic = has_dynamic_service_ref(&entry.rule_body);
        let body_services = io_services_from_rule_body(&entry.rule_body);
        for dep in &entry.dependencies {
            if !declared_services.contains(&dep.service_name) {
                return Err(BundleError::ServiceNotDeclared {
                    service: dep.service_name.clone(),
                });
            }
            if !has_dynamic && !body_services.contains(&dep.service_name) {
                return Err(BundleError::ServiceNotInRuleBody {
                    service: dep.service_name.clone(),
                });
            }
        }
        Ok(())
    }

    /// Knowledge 条目门禁（D3 领域 schema 强校验，fail-fast）
    fn validate_knowledge_entry(
        entry: &BundleEntry,
        schema_resolver: DomainSchemaResolver<'_>,
    ) -> Result<(), BundleError> {
        // 1) 服务依赖：MVP 不支持（显式拒绝，不静默忽略）
        if !entry.dependencies.is_empty() {
            return Err(BundleError::KnowledgeWithDependencies {
                entry: entry.entry_id.clone(),
            });
        }
        // 2) schema_ref 必填
        let uri = entry.schema_ref.as_deref().unwrap_or("");
        if uri.is_empty() {
            return Err(BundleError::KnowledgeMissingSchemaRef {
                entry: entry.entry_id.clone(),
            });
        }
        // 3) resolver 必须命中（未注册 = 拒绝，不静默放行）
        let schema = schema_resolver(uri).ok_or_else(|| BundleError::SchemaNotResolved {
            entry: entry.entry_id.clone(),
            uri: uri.to_string(),
        })?;
        // 4) payload 过领域 jsonschema 校验
        let validator = Validator::options()
            .with_draft(Draft::Draft202012)
            .build(&schema)
            .map_err(|e| BundleError::PayloadSchemaViolation {
                entry: entry.entry_id.clone(),
                uri: uri.to_string(),
                errors: vec![format!("领域 schema 本身非法: {e}")],
            })?;
        let errors: Vec<String> = match validator.validate(&entry.rule_body) {
            Ok(()) => Vec::new(),
            Err(iter) => iter
                .map(|e| {
                    let path = e.instance_path.to_string();
                    if path.is_empty() {
                        e.to_string()
                    } else {
                        format!("{path}: {e}")
                    }
                })
                .collect(),
        };
        if errors.is_empty() {
            Ok(())
        } else {
            Err(BundleError::PayloadSchemaViolation {
                entry: entry.entry_id.clone(),
                uri: uri.to_string(),
                errors,
            })
        }
    }

    /// 数据集级 push 事件声明门禁（段B B5）：与 Knowledge 条目同一 resolver 体系。
    ///
    /// - 事件名唯一（重名显式拒绝，不静默覆盖）；
    /// - schema_ref 非空 + resolver 必须命中 + schema 本身可构建校验器
    ///   （声明侧无实例数据，校验到 schema 合法性为止；实例校验由事件消费方执行）。
    fn validate_event_schemas(
        decls: &[EventSchemaDecl],
        schema_resolver: DomainSchemaResolver<'_>,
    ) -> Result<(), BundleError> {
        let mut seen: HashSet<&str> = HashSet::new();
        for decl in decls {
            if !seen.insert(decl.name.as_str()) {
                return Err(BundleError::EventSchemaDuplicate {
                    name: decl.name.clone(),
                });
            }
            let uri = decl.schema_ref.trim();
            if uri.is_empty() {
                return Err(BundleError::EventSchemaMissingRef {
                    name: decl.name.clone(),
                });
            }
            let schema =
                schema_resolver(uri).ok_or_else(|| BundleError::EventSchemaNotResolved {
                    name: decl.name.clone(),
                    uri: uri.to_string(),
                })?;
            if let Err(e) = Validator::options()
                .with_draft(Draft::Draft202012)
                .build(&schema)
            {
                return Err(BundleError::EventSchemaInvalid {
                    name: decl.name.clone(),
                    uri: uri.to_string(),
                    errors: vec![format!("领域 schema 本身非法: {e}")],
                });
            }
        }
        Ok(())
    }
}

/// 裁剪（服务公司，36 号 §5）：裁剪 = 原版本视图，不新造版本链
pub struct BundleTrimmer;

impl BundleTrimmer {
    /// 按条目 ID 精确裁剪
    pub fn trim_by_ids(
        bundle: &DatasetBundle,
        keep_ids: &[String],
        by: &str,
        at: &str,
    ) -> Result<DatasetBundle, BundleError> {
        let entries: Vec<BundleEntry> = bundle
            .entries
            .iter()
            .filter(|e| keep_ids.iter().any(|id| id == &e.entry_id))
            .cloned()
            .collect();
        if entries.is_empty() {
            return Err(BundleError::EmptyView);
        }
        Self::build_view(bundle, entries, by, at)
    }

    /// 按领域/标签过滤裁剪（标签命中任一即可）
    pub fn trim_by_filter(
        bundle: &DatasetBundle,
        domain: Option<&str>,
        tags: &[&str],
        by: &str,
        at: &str,
    ) -> Result<DatasetBundle, BundleError> {
        let entries: Vec<BundleEntry> = bundle
            .entries
            .iter()
            .filter(|e| {
                domain.map(|d| e.domain == d).unwrap_or(true)
                    && (tags.is_empty() || tags.iter().any(|t| e.tags.iter().any(|et| et == t)))
            })
            .cloned()
            .collect();
        if entries.is_empty() {
            return Err(BundleError::EmptyView);
        }
        Self::build_view(bundle, entries, by, at)
    }

    /// 构造视图：依赖收缩 + 视图引用 + 审计重算（36 号 §5）
    fn build_view(
        bundle: &DatasetBundle,
        entries: Vec<BundleEntry>,
        by: &str,
        at: &str,
    ) -> Result<DatasetBundle, BundleError> {
        // 依赖收缩：只留被裁规则实际用到的服务；引用未声明服务 → 显式报错（不静默丢弃）
        let used: HashSet<&str> = entries
            .iter()
            .flat_map(|e| e.dependencies.iter().map(|d| d.service_name.as_str()))
            .collect();
        let mut dd = bundle.data_dependencies.clone().unwrap_or_default();
        for svc in &used {
            if !dd.has_service(svc) {
                return Err(BundleError::ServiceNotDeclared {
                    service: svc.to_string(),
                });
            }
        }
        dd.services
            .retain(|s| used.contains(s.service_name.as_str()));

        let mut view = bundle.clone();
        view.bundle_id = format!("{}_view", bundle.bundle_id);
        view.dataset.view_of = Some(ViewRef {
            original_dataset_id: bundle.dataset.dataset_id.clone(),
            view_of_version: bundle.audit.source_version.clone(),
        });
        view.entries = entries;
        view.data_dependencies = if dd.services.is_empty() && dd.inputs.is_empty() {
            None
        } else {
            Some(dd)
        };
        // 审计重算（新导出者 + 新哈希）
        view.audit.exported_at = at.into();
        view.audit.exported_by = by.into();
        let hash = view.compute_content_hash();
        view.audit.content_hash = hash;
        Ok(view)
    }
}

/// 条目查询表达式（B3 段B 14 号，SSOT）—— 与 bundle subset 裁剪语法同族的纯函数过滤核。
///
/// 语法：多段以 `;` 分隔，**交集语义**；段格式 `kind:value`：
/// - `tag:core`：标签命中（任一标签相等即命中）
/// - `domain:tax`：领域精确匹配
/// - `ids:id1,id2`：条目 ID 精确命中（逗号分隔）
/// - `kind:rule|knowledge`：条目类型
/// - `q:子串`：子串命中 entry_id / domain / tags / rule_body 序列化文本
///
/// 非法段显式报错（不静默忽略，既有纪律）；空段跳过；返回保持原顺序。
pub struct EntryFilter;

impl EntryFilter {
    /// 解析并应用过滤表达式。先整段校验（任一非法段即整体拒绝，不部分应用），再逐段过滤。
    pub fn apply(entries: &[BundleEntry], spec: &str) -> Result<Vec<BundleEntry>, BundleError> {
        let mut segs: Vec<(&str, &str)> = Vec::new();
        for seg in spec.split(';') {
            let seg = seg.trim();
            if seg.is_empty() {
                continue;
            }
            let Some((kind, value)) = seg.split_once(':') else {
                return Err(BundleError::BadFilterSegment(seg.into()));
            };
            let value = value.trim();
            if value.is_empty() {
                return Err(BundleError::BadFilterSegment(seg.into()));
            }
            match kind {
                "tag" | "domain" | "ids" | "q" => {}
                "kind" => {
                    if value != "rule" && value != "knowledge" {
                        return Err(BundleError::BadFilterSegment(seg.into()));
                    }
                }
                _ => return Err(BundleError::BadFilterSegment(seg.into())),
            }
            segs.push((kind, value));
        }
        let mut out: Vec<BundleEntry> = entries.to_vec();
        for (kind, value) in segs {
            out.retain(|e| Self::matches(e, kind, value));
        }
        Ok(out)
    }

    /// 单段匹配判定（`kind`/`value` 已经过 apply 的段合法性校验）
    fn matches(e: &BundleEntry, kind: &str, value: &str) -> bool {
        match kind {
            "tag" => e.tags.iter().any(|t| t == value),
            "domain" => e.domain == value,
            "ids" => value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .any(|id| id == e.entry_id),
            "kind" => match value {
                "rule" => e.entry_kind == EntryKind::Rule,
                _ => e.entry_kind == EntryKind::Knowledge,
            },
            "q" => {
                let body = serde_json::to_string(&e.rule_body).unwrap_or_default();
                e.entry_id.contains(value)
                    || e.domain.contains(value)
                    || e.tags.iter().any(|t| t.contains(value))
                    || body.contains(value)
            }
            // apply 已校验，其余分支不可达
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{DataDependencies, InputDecl, ServiceDecl, SourceBinding};
    use crate::provenance::Provenance;
    use crate::version::{BumpKind, LawRef, VersionSelection, Versioning};

    /// 直接构造快照包（不依赖治理侧 RuleDataset/RuleEntry —— BundleExporter 留在 evorule-rule）
    fn bundle_with_entries(entries: Vec<BundleEntry>) -> DatasetBundle {
        DatasetBundle {
            bundle_schema_version: BUNDLE_SCHEMA_VERSION.into(),
            bundle_id: "bundle-ds-tax-2024-v1".into(),
            dataset: BundleDatasetMeta {
                dataset_id: "ds-tax-2024".into(),
                name: "2024 年度企业所得税合规规则集".into(),
                tenant_id: "org-evorule".into(),
                instance_id: "org-evorule".into(),
                versioning: Versioning::default(),
                law_ref: Some(LawRef {
                    document_id: "gov-tax-2023-001".into(),
                    law_version: Some("2023 修订版".into()),
                    effective_from: Some("2024-01-01".into()),
                    effective_to: None,
                }),
                version_selection: Some(VersionSelection {
                    mode: VersionSelectionMode::AutoByEffectiveDate,
                    pinned_version: None,
                    pinned_include_patch: None,
                }),
                view_of: None,
                event_schemas: vec![],
            },
            entries,
            data_dependencies: Some(DataDependencies {
                inputs: vec![InputDecl {
                    name: "payroll_event".into(),
                    schema: None,
                    description: None,
                    empty_allowed: false,
                }],
                services: vec![ServiceDecl {
                    service_name: "payroll_svc".into(),
                    version: None,
                    io_contract: None,
                    sensitive: false,
                    description: None,
                    template: None,
                }],
            }),
            tests: passed_tests(),
            audit: BundleAudit {
                exported_at: "2026-08-21T12:00:00Z".into(),
                exported_by: "publisher-01".into(),
                source_version: "v1".into(),
                content_hash: String::new(),
                hash_algo: "blake3".into(),
            },
        }
    }

    fn entry(entry_id: &str, domain: &str) -> BundleEntry {
        BundleEntry {
            entry_id: entry_id.into(),
            entry_kind: EntryKind::Rule,
            rule_body: serde_json::json!({
                "rule_id": entry_id,
                "version": "0.1.0",
                "transform": [
                    { "type": "io_request", "params": { "service_name": "payroll_svc" } }
                ]
            }),
            schema_ref: None,
            provenance: Provenance {
                source: "《企业所得税法》".into(),
                clause: None,
                document_id: None,
                effective_from: Some("2024-01-01".into()),
                effective_to: None,
                last_verified: None,
                verified_by: None,
            },
            domain: domain.into(),
            tags: vec![domain.into()],
            dependencies: vec![SourceBinding {
                rule_ref: "transform[0]".into(),
                service_name: "payroll_svc".into(),
            }],
        }
    }

    /// 空解析器（规则包测试用：rule 条目不触达 resolver）
    fn no_resolver(_: &str) -> Option<serde_json::Value> {
        None
    }

    // B3（段B 14 号）：EntryFilter 条目查询表达式纯函数

    fn filter_ids(entries: &[BundleEntry], spec: &str) -> Vec<String> {
        EntryFilter::apply(entries, spec)
            .unwrap()
            .into_iter()
            .map(|e| e.entry_id)
            .collect()
    }

    #[test]
    fn test_entry_filter_segments() {
        let entries = vec![entry("e1", "tax"), entry("e2", "tax"), {
            let mut e = entry("e3", "rpsm");
            e.tags.push("core".into());
            e
        }];
        // domain 精确
        assert_eq!(filter_ids(&entries, "domain:rpsm"), vec!["e3"]);
        // tag 任一命中
        assert_eq!(filter_ids(&entries, "tag:core"), vec!["e3"]);
        // ids 逗号列表
        assert_eq!(filter_ids(&entries, "ids:e1, e3"), vec!["e1", "e3"]);
        // q 子串命中 entry_id
        assert_eq!(filter_ids(&entries, "q:e2"), vec!["e2"]);
        // q 子串命中 rule_body 序列化文本（rule_id 字段值）
        assert_eq!(filter_ids(&entries, "q:e1"), vec!["e1"]);
        // 多段交集
        assert_eq!(
            filter_ids(&entries, "domain:tax;ids:e1,e2;q:e2"),
            vec!["e2"]
        );
        // 空段跳过 / 空表达式全量
        assert_eq!(filter_ids(&entries, ";"), vec!["e1", "e2", "e3"]);
        assert_eq!(filter_ids(&entries, ""), vec!["e1", "e2", "e3"]);
    }

    #[test]
    fn test_entry_filter_rejects_bad_segments() {
        let entries = vec![entry("e1", "tax")];
        for bad in ["noseg", "kind:whatever", "tag:", "domain:", "ids:", "q: "] {
            let err = EntryFilter::apply(&entries, bad).unwrap_err();
            assert!(
                matches!(err, BundleError::BadFilterSegment(_)),
                "{bad}: {err}"
            );
        }
        // 非法段整体拒绝：不部分应用（任一非法段 → Err，无副作用）
        let err = EntryFilter::apply(&entries, "domain:tax;noseg").unwrap_err();
        assert!(matches!(err, BundleError::BadFilterSegment(_)));
    }

    #[test]
    fn test_entry_filter_kind_segment() {
        let mut k = entry("k1", "rpsm");
        k.entry_kind = EntryKind::Knowledge;
        k.schema_ref = Some("https://rpsm.evorule.org/schemas/scenario/v1.0.json".into());
        let entries = vec![entry("e1", "tax"), k];
        assert_eq!(filter_ids(&entries, "kind:rule"), vec!["e1"]);
        assert_eq!(filter_ids(&entries, "kind:knowledge"), vec!["k1"]);
        assert_eq!(
            filter_ids(&entries, "kind:knowledge;domain:rpsm"),
            vec!["k1"]
        );
    }

    /// 模拟 rpsm 场景领域 schema（resolver 注入用；领域 schema 归领域仓，此处仅测试替身）
    fn scenario_schema() -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["scenario_id", "gravity", "bodies"],
            "properties": {
                "scenario_id": {"type": "string"},
                "gravity": {"type": "array", "items": {"type": "number"}, "minItems": 3, "maxItems": 3},
                "restitution": {"type": "number", "minimum": 0, "maximum": 1},
                "bodies": {"type": "array", "items": {"type": "object"}}
            }
        })
    }

    /// 命中 rpsm 场景 schema URI 的解析器
    fn scenario_resolver(uri: &str) -> Option<serde_json::Value> {
        (uri == "https://rpsm.evorule.org/schemas/scenario/v1.0.json").then_some(scenario_schema())
    }

    /// knowledge 数据条目（rpsm 场景形态）
    fn knowledge_entry(entry_id: &str) -> BundleEntry {
        BundleEntry {
            entry_id: entry_id.into(),
            entry_kind: EntryKind::Knowledge,
            rule_body: serde_json::json!({
                "scenario_id": "spring-single-particle",
                "gravity": [0.0, -9.81, 0.0],
                "restitution": 1.0,
                "bodies": [{"id": "particle-1"}]
            }),
            schema_ref: Some("https://rpsm.evorule.org/schemas/scenario/v1.0.json".into()),
            provenance: Provenance {
                source: "rpsm 内置场景".into(),
                clause: None,
                document_id: None,
                effective_from: None,
                effective_to: None,
                last_verified: None,
                verified_by: None,
            },
            domain: "physics".into(),
            tags: vec!["physics".into()],
            dependencies: vec![],
        }
    }

    fn passed_tests() -> BundleTests {
        BundleTests {
            subset: vec!["case-1".into()],
            fixtures: vec!["fx-payroll-1".into()],
            verdict: TestVerdict::Pass,
        }
    }

    fn exported_bundle() -> DatasetBundle {
        let mut b = bundle_with_entries(vec![
            entry("entry-tax-001", "tax"),
            entry("entry-labor-002", "labor"),
        ]);
        resign(&mut b); // 直接构造（非 BundleExporter）→ 需签名哈希
        b
    }

    /// 测试辅助：模拟"按当前内容重新签名导出"（使结构校验前的哈希校验通过）
    fn resign(b: &mut DatasetBundle) {
        let h = b.compute_content_hash();
        b.audit.content_hash = h;
    }

    #[test]
    fn test_export_bundle_fields_and_hash() {
        let bundle = exported_bundle();
        assert_eq!(bundle.bundle_schema_version, "1.0");
        assert_eq!(bundle.audit.source_version, "v1");
        assert_eq!(bundle.dataset.instance_id, "org-evorule");
        assert_eq!(bundle.entries.len(), 2);
        assert!(bundle.audit.content_hash.starts_with("blake3:"));
        // 防篡改校验通过；改一处内容 → 校验失败
        bundle.verify_content_hash().unwrap();
        let mut tampered = bundle.clone();
        tampered.entries[0].rule_body = serde_json::json!({"rule_id": "hacked"});
        assert!(matches!(
            tampered.verify_content_hash(),
            Err(BundleError::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn test_import_valid_bundle() {
        let bundle = exported_bundle();
        let r = BundleImporter::validate(&bundle, &no_resolver).unwrap();
        assert_eq!(r.dataset_id, "ds-tax-2024");
        assert_eq!(r.entry_count, 2);
        assert_eq!(r.selection_mode, VersionSelectionMode::AutoByEffectiveDate);
        assert_eq!(r.resolved_version, None); // auto 运行时解析
        assert_eq!(r.verdict, TestVerdict::Pass);
    }

    #[test]
    fn test_import_rejects_unsupported_schema() {
        let mut b = exported_bundle();
        b.bundle_schema_version = "2.0".into();
        match BundleImporter::validate(&b, &no_resolver) {
            Err(BundleError::UnsupportedSchema { found }) => assert_eq!(found, "2.0"),
            _ => panic!("expected UnsupportedSchema"),
        }
    }

    #[test]
    fn test_import_rejects_fail_verdict() {
        let mut b = exported_bundle();
        b.tests.verdict = TestVerdict::Fail;
        resign(&mut b);
        let err = BundleImporter::validate(&b, &no_resolver).unwrap_err();
        assert!(matches!(err, BundleError::TestsNotPassed { .. }));
    }

    #[test]
    fn test_import_rejects_undeclared_service() {
        let bundle = exported_bundle();
        // 构造：条目依赖未在 data_dependencies 声明的服务
        let mut b = bundle.clone();
        b.entries[0].dependencies[0].service_name = "ghost_svc".into();
        resign(&mut b);
        match BundleImporter::validate(&b, &no_resolver) {
            Err(BundleError::ServiceNotDeclared { service }) => assert_eq!(service, "ghost_svc"),
            _ => panic!("expected ServiceNotDeclared"),
        }
    }

    #[test]
    fn test_import_rejects_service_not_in_rule_body() {
        let bundle = exported_bundle();
        let mut b = bundle.clone();
        // 结构合法（set 指令）但 rule_body 无 payroll_svc 的 io_request 引用
        b.entries[0].rule_body = serde_json::json!({
            "rule_id": "entry-tax-001",
            "transform": [{"type": "set", "params": {"x": 1}}]
        });
        resign(&mut b);
        match BundleImporter::validate(&b, &no_resolver) {
            Err(BundleError::ServiceNotInRuleBody { service }) => {
                assert_eq!(service, "payroll_svc")
            }
            _ => panic!("expected ServiceNotInRuleBody"),
        }
    }

    #[test]
    fn test_validate_entry_rejects_invalid_structure() {
        // C8 SSOT 门禁：结构非法 rule_body（空 transform）→ InvalidEntryStructure
        let entry = BundleEntry {
            entry_id: "e1".into(),
            entry_kind: EntryKind::Rule,
            rule_body: serde_json::json!({"rule_id": "e1", "transform": []}),
            schema_ref: None,
            provenance: Provenance {
                source: "test".into(),
                clause: None,
                document_id: None,
                effective_from: None,
                effective_to: None,
                last_verified: None,
                verified_by: None,
            },
            domain: "tax".into(),
            tags: vec![],
            dependencies: vec![],
        };
        let declared = vec!["payroll_svc".to_string()];
        let err = BundleImporter::validate_entry(&entry, &declared, &no_resolver).unwrap_err();
        assert!(
            matches!(err, BundleError::InvalidEntryStructure { ref entry, .. } if entry == "e1")
        );
    }

    // ===== Q12 数据资产化：knowledge 条目门禁（D3 领域 schema 强校验）=====

    #[test]
    fn test_knowledge_entry_passes_with_resolver() {
        let declared: Vec<String> = vec![];
        BundleImporter::validate_entry(
            &knowledge_entry("d-scenario-1"),
            &declared,
            &scenario_resolver,
        )
        .unwrap();
    }

    #[test]
    fn test_knowledge_entry_requires_schema_ref() {
        let mut e = knowledge_entry("d-no-ref");
        e.schema_ref = None;
        let err = BundleImporter::validate_entry(&e, &[], &scenario_resolver).unwrap_err();
        assert!(matches!(
            err,
            BundleError::KnowledgeMissingSchemaRef { ref entry } if entry == "d-no-ref"
        ));
    }

    #[test]
    fn test_knowledge_entry_resolver_miss_rejected() {
        // fail-fast：schema_ref 指向未注册 URI → 拒绝（不静默放行）
        let mut e = knowledge_entry("d-unknown-ref");
        e.schema_ref = Some("https://unknown.example/schema.json".into());
        let err = BundleImporter::validate_entry(&e, &[], &scenario_resolver).unwrap_err();
        assert!(matches!(
            err,
            BundleError::SchemaNotResolved { ref entry, ref uri }
                if entry == "d-unknown-ref" && uri == "https://unknown.example/schema.json"
        ));
    }

    #[test]
    fn test_knowledge_entry_payload_violation_rejected() {
        // D3 强校验：payload 违反领域 schema（gravity 2 维 < minItems 3）→ 拒绝
        let mut e = knowledge_entry("d-bad-payload");
        e.rule_body = serde_json::json!({
            "scenario_id": "bad",
            "gravity": [0.0, -9.81],
            "bodies": []
        });
        let err = BundleImporter::validate_entry(&e, &[], &scenario_resolver).unwrap_err();
        assert!(matches!(
            err,
            BundleError::PayloadSchemaViolation { ref entry, .. } if entry == "d-bad-payload"
        ));
    }

    #[test]
    fn test_knowledge_entry_with_dependencies_rejected() {
        // 数据条目不经 io_request 消费服务：携带服务依赖显式拒绝（不静默忽略）
        let mut e = knowledge_entry("d-with-dep");
        e.dependencies = vec![SourceBinding {
            rule_ref: "n/a".into(),
            service_name: "payroll_svc".into(),
        }];
        let err =
            BundleImporter::validate_entry(&e, &["payroll_svc".to_string()], &scenario_resolver)
                .unwrap_err();
        assert!(matches!(
            err,
            BundleError::KnowledgeWithDependencies { ref entry } if entry == "d-with-dep"
        ));
    }

    #[test]
    fn test_mixed_bundle_validates() {
        // 规则条目 + 数据条目混排同一数据集：双门禁各走各路
        let mut b = bundle_with_entries(vec![
            entry("entry-tax-001", "tax"),
            knowledge_entry("d-scenario-1"),
        ]);
        resign(&mut b);
        BundleImporter::validate(&b, &scenario_resolver).unwrap();
    }

    #[test]
    fn test_legacy_bundle_json_defaults_to_rule() {
        // 旧格式（无 entry_kind 字段）反序列化 → Rule 条目，向后兼容
        let raw = serde_json::json!({
            "entry_id": "legacy-1",
            "rule_body": {"rule_id": "legacy-1", "transform": [
                {"type": "io_request", "params": {"service_name": "payroll_svc"}}
            ]},
            "provenance": {"source": "legacy"},
            "domain": "tax",
            "dependencies": [{"rule_ref": "transform[0]", "service_name": "payroll_svc"}]
        });
        let e: BundleEntry = serde_json::from_value(raw).unwrap();
        assert_eq!(e.entry_kind, EntryKind::Rule);
        assert_eq!(e.schema_ref, None);
        let declared = vec!["payroll_svc".to_string()];
        BundleImporter::validate_entry(&e, &declared, &no_resolver).unwrap();
    }

    #[test]
    fn test_knowledge_bundle_end_to_end_import() {
        // 全 knowledge 数据集：构造 → 签名 → 导入校验通过（闸门一证据 pass）
        let mut b = bundle_with_entries(vec![knowledge_entry("d-scenario-1")]);
        // knowledge 数据集无服务依赖
        b.data_dependencies = None;
        resign(&mut b);
        let r = BundleImporter::validate(&b, &scenario_resolver).unwrap();
        assert_eq!(r.entry_count, 1);
        assert_eq!(r.verdict, TestVerdict::Pass);
    }

    // ===== 段B B5：数据集级 push 事件 schema 声明 =====

    use crate::dependency::EventSchemaDecl;

    fn event_decl(name: &str, uri: &str) -> EventSchemaDecl {
        EventSchemaDecl {
            name: name.into(),
            schema_ref: uri.into(),
            direction: Default::default(),
            description: None,
        }
    }

    #[test]
    fn test_event_schemas_roundtrip_and_import() {
        // 测试门①：声明随包携带，经 JSON 往返不丢失，导入校验通过
        let mut b = exported_bundle();
        b.dataset.event_schemas = vec![event_decl(
            "payroll_event",
            "https://rpsm.evorule.org/schemas/scenario/v1.0.json",
        )];
        resign(&mut b);
        let json = serde_json::to_string(&b).unwrap();
        let back: DatasetBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dataset.event_schemas, b.dataset.event_schemas);
        assert_eq!(back.dataset.event_schemas[0].name, "payroll_event");
        BundleImporter::validate(&back, &scenario_resolver).unwrap();
    }

    #[test]
    fn test_event_schema_unknown_ref_rejected() {
        // 测试门②：schema_ref 指向未注册 URI → 导入显式拒绝（fail-fast）
        let mut b = exported_bundle();
        b.dataset.event_schemas = vec![event_decl("e1", "https://unknown.example/e.json")];
        resign(&mut b);
        let err = BundleImporter::validate(&b, &scenario_resolver).unwrap_err();
        assert!(matches!(
            err,
            BundleError::EventSchemaNotResolved { ref name, ref uri }
                if name == "e1" && uri == "https://unknown.example/e.json"
        ));
    }

    #[test]
    fn test_event_schema_duplicate_and_missing_ref_rejected() {
        // 事件名重复 → 显式拒绝（不静默覆盖）
        let mut b = exported_bundle();
        let uri = "https://rpsm.evorule.org/schemas/scenario/v1.0.json";
        b.dataset.event_schemas = vec![event_decl("e1", uri), event_decl("e1", uri)];
        resign(&mut b);
        let err = BundleImporter::validate(&b, &scenario_resolver).unwrap_err();
        assert!(matches!(
            err,
            BundleError::EventSchemaDuplicate { ref name } if name == "e1"
        ));
        // schema_ref 空 → 显式拒绝（D3 强校验）
        let mut b2 = exported_bundle();
        b2.dataset.event_schemas = vec![event_decl("e1", "   ")];
        resign(&mut b2);
        let err = BundleImporter::validate(&b2, &scenario_resolver).unwrap_err();
        assert!(matches!(
            err,
            BundleError::EventSchemaMissingRef { ref name } if name == "e1"
        ));
    }

    #[test]
    fn test_legacy_bundle_without_event_schemas_defaults_empty() {
        // 测试门③：存量数据集/旧格式包（无 event_schemas 字段）→ 缺省空，零迁移回归
        let mut b = exported_bundle();
        b.dataset.event_schemas = vec![];
        let json = serde_json::to_string(&b).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // 模拟旧格式：整个字段不存在（skip_serializing_if 已不写出，此处显式删除再验）
        if let Some(ds) = v.get_mut("dataset").and_then(|d| d.as_object_mut()) {
            ds.remove("event_schemas");
        }
        let back: DatasetBundle = serde_json::from_value(v).unwrap();
        assert!(back.dataset.event_schemas.is_empty());
        BundleImporter::validate(&back, &no_resolver).unwrap();
    }

    #[test]
    fn test_import_pinned_resolves() {
        let mut b = exported_bundle();
        // 升一个版本并设 pinned
        b.dataset.versioning = b.dataset.versioning.bump(BumpKind::Patch).unwrap(); // v1.p1
        b.dataset.version_selection = Some(VersionSelection {
            mode: VersionSelectionMode::Pinned,
            pinned_version: Some("v1".into()),
            pinned_include_patch: None,
        });
        resign(&mut b);
        let r = BundleImporter::validate(&b, &no_resolver).unwrap();
        assert_eq!(r.resolved_version.as_deref(), Some("v1.p1")); // 同主版本最新 Patch
        assert_eq!(r.selection_mode, VersionSelectionMode::Pinned);
    }

    #[test]
    fn test_import_auto_requires_effective_base() {
        let mut b = exported_bundle();
        b.dataset.law_ref = None;
        resign(&mut b);
        let err = BundleImporter::validate(&b, &no_resolver).unwrap_err();
        assert!(matches!(err, BundleError::MissingEffectiveBase));
    }

    #[test]
    fn test_trim_by_ids_is_view() {
        let bundle = exported_bundle();
        let view = BundleTrimmer::trim_by_ids(
            &bundle,
            &["entry-tax-001".into()],
            "si-company",
            "2026-08-21T14:00:00Z",
        )
        .unwrap();
        // 只留 1 条
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].entry_id, "entry-tax-001");
        // 视图引用：指向原数据集与版本，不新造版本号
        let v = view.dataset.view_of.as_ref().unwrap();
        assert_eq!(v.original_dataset_id, "ds-tax-2024");
        assert_eq!(v.view_of_version, "v1");
        assert_eq!(view.dataset.versioning, bundle.dataset.versioning); // 版本链不变
        assert_eq!(view.audit.source_version, "v1");
        // 依赖收缩：payroll_svc 仍在使用；inputs 保留
        assert!(view
            .data_dependencies
            .as_ref()
            .unwrap()
            .has_service("payroll_svc"));
        // 审计重算：新导出者 + 新哈希
        assert_eq!(view.audit.exported_by, "si-company");
        view.verify_content_hash().unwrap();
        // 视图仍是合法可导入包
        BundleImporter::validate(&view, &no_resolver).unwrap();
    }

    #[test]
    fn test_trim_by_filter_domain() {
        let bundle = exported_bundle();
        let view =
            BundleTrimmer::trim_by_filter(&bundle, Some("labor"), &[], "si-company", "t").unwrap();
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].domain, "labor");
    }

    #[test]
    fn test_trim_empty_rejected() {
        let bundle = exported_bundle();
        let err = BundleTrimmer::trim_by_ids(&bundle, &["nope".into()], "x", "t").unwrap_err();
        assert!(matches!(err, BundleError::EmptyView));
        let err = BundleTrimmer::trim_by_filter(&bundle, Some("nope"), &[], "x", "t").unwrap_err();
        assert!(matches!(err, BundleError::EmptyView));
    }
}
