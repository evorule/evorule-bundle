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

use serde::{Deserialize, Serialize};
use evorule_hash;
use thiserror::Error;

use crate::dependency::{DataDependencies, SourceBinding};
use crate::provenance::Provenance;
use crate::resolve::{ResolveError, VersionResolver};
use crate::structure::validate_rule_structure;
use crate::symbols::{has_dynamic_service_ref, io_services_from_rule_body};
use crate::version::{
    LawRef, VersionError, VersionSelection, VersionSelectionMode, Versioning,
};

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

    #[error("auto_by_effective_date 模式需快照包携带 law_ref.effective_from 作为生效基准")]
    MissingEffectiveBase,

    #[error("沙箱验证未通过（tests.verdict={verdict:?}），拒绝导入（闸门一证据）")]
    TestsNotPassed { verdict: TestVerdict },

    #[error("裁剪结果为空（所选条件无匹配条目）")]
    EmptyView,

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
}

/// 快照包条目（36 号 §2 entries 段，rule_body 原生 JSON）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleEntry {
    pub entry_id: String,
    /// evorule 原生 JSON，零转译
    pub rule_body: serde_json::Value,
    /// 溯源不丢出处
    pub provenance: Provenance,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// 条目级依赖（裁剪后收缩）
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
    pub fn validate(bundle: &DatasetBundle) -> Result<ImportResult, BundleError> {
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
            Self::validate_entry(entry, &declared)?;
        }
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
    /// 1) rule_body 结构（引擎原生 transform 形态，防 loader fail-soft 静默跳过非法规则）；
    /// 2) 符号三方一致（31 号 §9-3）：dependencies 必须在数据集服务声明中，且在 rule_body
    ///    有 io_request 引用。动态 service 引用（`__exec__.instruction.params.*`）运行时解析，
    ///    body 字面量不参与匹配。
    ///
    /// `declared_services`：数据集 data_dependencies.services 的服务名列表。
    pub fn validate_entry(
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
        dd.services.retain(|s| used.contains(s.service_name.as_str()));

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
            rule_body: serde_json::json!({
                "rule_id": entry_id,
                "version": "0.1.0",
                "transform": [
                    { "type": "io_request", "params": { "service_name": "payroll_svc" } }
                ]
            }),
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

    fn passed_tests() -> BundleTests {
        BundleTests {
            subset: vec!["case-1".into()],
            fixtures: vec!["fx-payroll-1".into()],
            verdict: TestVerdict::Pass,
        }
    }

    fn exported_bundle() -> DatasetBundle {
        let mut b =
            bundle_with_entries(vec![entry("entry-tax-001", "tax"), entry("entry-labor-002", "labor")]);
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
        tampered.entries[0].rule_body =
            serde_json::json!({"rule_id": "hacked"});
        assert!(matches!(
            tampered.verify_content_hash(),
            Err(BundleError::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn test_import_valid_bundle() {
        let bundle = exported_bundle();
        let r = BundleImporter::validate(&bundle).unwrap();
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
        match BundleImporter::validate(&b) {
            Err(BundleError::UnsupportedSchema { found }) => assert_eq!(found, "2.0"),
            _ => panic!("expected UnsupportedSchema"),
        }
    }

    #[test]
    fn test_import_rejects_fail_verdict() {
        let mut b = exported_bundle();
        b.tests.verdict = TestVerdict::Fail;
        resign(&mut b);
        let err = BundleImporter::validate(&b).unwrap_err();
        assert!(matches!(err, BundleError::TestsNotPassed { .. }));
    }

    #[test]
    fn test_import_rejects_undeclared_service() {
        let bundle = exported_bundle();
        // 构造：条目依赖未在 data_dependencies 声明的服务
        let mut b = bundle.clone();
        b.entries[0].dependencies[0].service_name = "ghost_svc".into();
        resign(&mut b);
        match BundleImporter::validate(&b) {
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
        match BundleImporter::validate(&b) {
            Err(BundleError::ServiceNotInRuleBody { service }) => assert_eq!(service, "payroll_svc"),
            _ => panic!("expected ServiceNotInRuleBody"),
        }
    }

    #[test]
    fn test_validate_entry_rejects_invalid_structure() {
        // C8 SSOT 门禁：结构非法 rule_body（空 transform）→ InvalidEntryStructure
        let entry = BundleEntry {
            entry_id: "e1".into(),
            rule_body: serde_json::json!({"rule_id": "e1", "transform": []}),
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
        let err = BundleImporter::validate_entry(&entry, &declared).unwrap_err();
        assert!(matches!(err, BundleError::InvalidEntryStructure { ref entry, .. } if entry == "e1"));
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
        let r = BundleImporter::validate(&b).unwrap();
        assert_eq!(r.resolved_version.as_deref(), Some("v1.p1")); // 同主版本最新 Patch
        assert_eq!(r.selection_mode, VersionSelectionMode::Pinned);
    }

    #[test]
    fn test_import_auto_requires_effective_base() {
        let mut b = exported_bundle();
        b.dataset.law_ref = None;
        resign(&mut b);
        let err = BundleImporter::validate(&b).unwrap_err();
        assert!(matches!(err, BundleError::MissingEffectiveBase));
    }

    #[test]
    fn test_trim_by_ids_is_view() {
        let bundle = exported_bundle();
        let view = BundleTrimmer::trim_by_ids(&bundle, &["entry-tax-001".into()], "si-company", "2026-08-21T14:00:00Z")
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
        assert!(view.data_dependencies.as_ref().unwrap().has_service("payroll_svc"));
        // 审计重算：新导出者 + 新哈希
        assert_eq!(view.audit.exported_by, "si-company");
        view.verify_content_hash().unwrap();
        // 视图仍是合法可导入包
        BundleImporter::validate(&view).unwrap();
    }

    #[test]
    fn test_trim_by_filter_domain() {
        let bundle = exported_bundle();
        let view = BundleTrimmer::trim_by_filter(&bundle, Some("labor"), &[], "si-company", "t").unwrap();
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
