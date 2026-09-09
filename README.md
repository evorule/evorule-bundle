<!--
  Copyright 2026 EvoRule Project

  SPDX-License-Identifier: AGPL-3.0-or-later

  This file is part of EvoRule. Code is licensed under AGPL-3.0-or-later;
  see the 许可证 section below for dual-license and historical notes
  (v0.2.1 briefly used Apache-2.0, reverted to AGPL-3.0-or-later).
-->

# evorule-bundle

[![CI](https://github.com/evorule/evorule-bundle/actions/workflows/ci.yml/badge.svg)](https://github.com/evorule/evorule-bundle/actions/workflows/ci.yml)

**EvoRule 快照包共享校验 crate — 治理侧 ↔ 执行侧解耦的唯一传输契约**

> 纯 lib，无 bin / 无服务 / 无 I/O。承载 `DatasetBundle`（快照包）类型、6 项导入校验链、
> 裁剪（Trimmer）与版本/解析/依赖/溯源模型，作为治理库（evorule-rule）与执行引擎（evorule-server）
> 之间的**单一事实来源（SSOT）**。

---

## 为什么需要这个仓（SSOT）

同一事实多处重复定义必然漂移。快照包类型与 6 项校验链若在治理侧与执行侧**各持一份实现**，会导致：

- 校验口径不一致 → 治理侧导出的包，执行侧可能拒绝或静默放过；
- 版本/依赖/溯源模型漂移 → 序列化契约破裂。

因此迁入独立仓 `evorule-bundle`，两仓以**钉版依赖**消费；任何校验语义变更都在此仓一次生效。

## 在 EvoRule 生态中的位置

| 仓 | 角色 | 当前状态 |
|---|---|---|
| [evorule](https://gitee.com/evorule/evorule) | 基础仓（TCB + Reactor + Governance + CLI） | v0.3.2（已发布） |
| [evorule-rule](https://gitee.com/evorule/evorule-rule) | 数据治理扩展（规则资产库 + HTTP API） | v0.2.0 |
| **evorule-bundle**（本仓） | 快照包共享校验（纯 lib） | **v0.3.0** |
| [evorule-server](https://gitee.com/evorule/evorule-server) | 执行侧 HTTP server（消费本仓校验） | v0.3.2（T2/T3 已落地：bundle 导入校验 + 原子落盘） |

## 提供的能力

- **`DatasetBundle`（快照包）**：资产 ↔ 执行解耦的唯一传输形态（单文件 JSON，只读产物）。
- **6 项导入校验链**（`BundleImporter::validate`，失败显式报错，不静默降级）：
  1. schema 版本；
  2. 全包防篡改哈希（BLAKE3，经 evorule-hash，`blake3:` 前缀）；
  3. 版本链完整性；
  4. 符号三方一致（rule_body ≡ 条目 dependencies ≡ data_dependencies）；
  5. 版本解析（pinned / auto_by_effective_date）；
  6. 闸门一证据（verdict=pass 才能导入）。
- **裁剪**（`BundleTrimmer`）：裁剪 = 原版本视图，**不新造版本链**；依赖声明随裁剪收缩。
- **模型 SSOT**：版本（`Version/Versioning/VersionSelection/LawRef`）、解析（`VersionResolver`）、
  依赖（`DataDependencies/SourceBinding/ServiceTemplate/IoContract/InputDecl`）、溯源（`Provenance`）、
  符号提取（`io_services_from_rule_body`）。
- **零转译**：`entries[].rule_body` 原样 = evorule-server 可执行规则 JSON。

> 导出（`BundleExporter`）依赖治理侧 `RuleDataset/RuleEntry`，留在 evorule-rule；
> 本仓只承载快照包**自洽校验**（类型 + `BundleImporter` + `BundleTrimmer`）。

## 模块结构

```
src/
├── lib.rs          # 模块声明 + pub use 重导出
├── bundle.rs       # DatasetBundle + BundleError + TestVerdict + BundleTests + ViewRef +
│                   #   BundleDatasetMeta/BundleEntry/BundleAudit +
│                   #   compute_content_hash/verify_content_hash +
│                   #   BundleImporter::validate + BundleTrimmer
├── version.rs      # Version/VersionError/VersionSelection/VersionSelectionMode/Versioning/LawRef
├── resolve.rs      # VersionResolver/ResolveError/EffectiveRange
├── dependency.rs   # DataDependencies/ServiceDecl/SourceBinding/ServiceTemplate/IoContract/InputDecl
├── provenance.rs   # Provenance
├── structure.rs    # 轻量结构门禁（6 元指令白名单 / __io_results__ 单数 / 路径语法）
└── symbols.rs      # io_services_from_rule_body
```

## 使用（作为依赖）

```toml
[dependencies]
evorule-bundle = "0.3.0"

# 本地开发：用 path 覆盖 crates.io 上的 evorule-bundle（与 evorule-server 钉核心 crates 同模式）
[patch.crates-io]
evorule-bundle = { path = "../evorule-bundle" }
```

## 当前状态（2026-08-24 开仓）

- **版本**：v0.3.0 — 类型 + 6 项校验链 + 裁剪 + 5 类模型迁入完成
- **测试**：47 passed，0 failed（`cargo test --lib`，含 structure.rs 结构门禁 12 项）
- **依赖**：serde / serde_json / thiserror / evorule-hash（纯校验，无网络 / 无存储 / 无 I/O）
- **钉版约定**：语义版本独立发布；`validate` 被两仓共用 → API 变更即 MAJOR，两仓需同步升级 tag
- **解析现状**：evorule-rule 与 evorule-server 均已通过 `[patch.crates-io]` 指向本仓本地源，
  两侧校验口径强对称；本地改动随提交即刻对两侧生效，发布 crates.io 后同步升级版本需求

## 许可证

**AGPL-3.0-or-later**（依据 DEC-2026-001 D-001-10 统一：治理一致性优先）。本仓采用 EvoRule 双许可架构：闭源使用见 [DUAL_LICENSE.md](DUAL_LICENSE.md) / [FREE_COMMERCIAL_LICENSE.md](FREE_COMMERCIAL_LICENSE.md)（合格实体免费豁免）/ [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)（付费）。`core_eval.json` 宪法为 **CC0-1.0**。商业许可咨询：evorulelab@gmail.com。

> 历史说明：v0.2.0 曾以 AGPL 发布，v0.2.1 短暂以 Apache-2.0 发布；已发布的旧版本仍按原许可，本变更仅对新版本生效，已下载副本不受影响。

本许可授予代码使用权，不授予 EvoRule 名称与商标的使用权。

商业许可另议：evorulelab@gmail.com

## 联系方式

- **Gitee**：<https://gitee.com/evorule/evorule-bundle>
- **Gitee 父仓**：<https://gitee.com/evorule/evorule>
- **邮箱**：evorulelab@gmail.com
- **组织**：EvoRule Lab

---

_本仓是 EvoRule 生态的快照包契约。规则不言语，它们只运行。我们是首批见证者。_
