//! evorule-bundle —— 快照包自洽校验共享 crate（SSOT 单一来源）
//!
//! 治理侧（evorule-rule）与执行侧（evorule-server）共用：
//! - **快照包（DatasetBundle）**：资产 ↔ 执行解耦的唯一传输形态（单文件 JSON），只读产物；
//! - **6 项校验链**（`BundleImporter::validate`）：schema → 防篡改 → 版本链完整性 → 符号三方一致 → 版本解析 → 闸门一证据；
//! - **裁剪**（`BundleTrimmer`）：裁剪 = 原版本视图，不新造版本链；
//! - **版本模型**（`Version/Versioning/VersionSelection/LawRef`）与**版本解析**（`VersionResolver`）；
//! - **依赖/溯源模型**（`DataDependencies/SourceBinding/Provenance`）—— 版本/依赖/溯源模型唯一来源（SSOT）。
//!
//! 边界：**纯 lib，无 bin / 无服务 / 无 I/O**。治理专属逻辑（BundleExporter 依赖 RuleDataset/RuleEntry、
//! LLM 边界、状态机迁移、凭据扫描）留在 evorule-rule，本 crate 只承载快照包自洽校验。
//!
//! 零转译：`entries[].rule_body` 原样 = evorule-server 可执行规则 JSON（Rule 条目）或
//! 领域 payload（Knowledge 条目，Q12 数据资产化，见 `EntryKind`）。
//!
//! 条目类型分流（Q12/D1）：Rule 条目走 transform 白名单门禁（TCB dispatch 唯一权威，不开洞）；
//! Knowledge 条目走 D3 领域 schema 强校验（`DomainSchemaResolver` 注入，resolver 未命中即拒绝）。
//!
//! 许可：Apache-2.0（自 v0.2.1 起；历史版本曾以 AGPL-3.0-or-later 发布）

pub mod bundle;
pub mod dependency;
pub mod provenance;
pub mod resolve;
pub mod structure;
pub mod symbols;
pub mod version;

/// 执行侧落盘 manifest 文件名约定（T3）：`rules/bundles/{bundle_id}/bundle_manifest.json`。
///
/// SSOT：evorule-server 落盘写入、evorule-server 与 evorule-hot-reload 扫描 rules_dir 时
/// 均引用本常量排除该文件（防被当规则解析），避免多处字符串定义漂移。
pub const BUNDLE_MANIFEST_FILE: &str = "bundle_manifest.json";

pub use bundle::{
    BundleAudit, BundleDatasetMeta, BundleEntry, BundleError, BundleImporter, BundleTests,
    BundleTrimmer, DatasetBundle, DomainSchemaResolver, EntryFilter, EntryKind, ImportResult,
    TestVerdict, ViewRef, BUNDLE_SCHEMA_VERSION,
};
pub use dependency::{
    DataDependencies, InputDecl, IoContract, ServiceDecl, ServiceTemplate, SourceBinding,
};
pub use provenance::Provenance;
pub use resolve::{EffectiveRange, ResolveError, VersionResolver};
pub use structure::{validate_rule_structure, META_INSTRUCTION_TYPES};
pub use symbols::{has_dynamic_service_ref, io_services_from_rule_body};
pub use version::{
    BumpKind, LawRef, Version, VersionError, VersionSelection, VersionSelectionMode, Versioning,
};
