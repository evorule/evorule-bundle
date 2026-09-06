<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 EvoRule Project -->

# 更新日志

本文件记录 evorule-bundle 的显著变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.2.1] - 2026-08-29

### 变更

- **许可证变更：AGPL-3.0-or-later → Apache-2.0**（自本版本起生效）。传输契约层宽松化以利于生态接入（"契约宽松 + 实现层 AGPL"分层模式）；Apache-2.0 授予代码使用权，不授予 EvoRule 商标
- 历史版本 v0.2.0 仍适用 AGPL-3.0-or-later（已发布版本不可撤回）

### 文档

- README 与实现对齐：哈希字段修正为 BLAKE3（经 evorule-hash，`blake3:` 前缀）；测试计数修正为 47 passed；模块结构补 `structure.rs`；生态表 server 状态更新为 v0.3.2、主仓版本对齐 v0.3.2
- 新增"解析现状"说明：evorule-rule 与 evorule-server 均已通过 `[patch.crates-io]` 指向本仓本地源，两侧校验口径强对称
- 建立版本控制基线与 CHANGELOG

## [0.2.0] - 2026-08-25

已发布至 crates.io（本地与发布版字节一致）。

### 新增

- `structure.rs`：轻量结构门禁——6 元指令白名单、`__io_results__` 单数形态、路径语法校验（12 项测试）
- `symbols.rs`：`io_services_from_rule_body`（规则体 io_request 服务名提取）
- 防篡改哈希经 `evorule-hash` 接入（BLAKE3，`blake3:` 前缀）

### 说明

- 校验链共 6 项：结构 → schema → 白名单 → 符号 → 哈希 → 元数据
- 测试 47 passed / 0 failed（`cargo test --lib`）
- 依赖：serde / serde_json / thiserror / evorule-hash（纯校验，无网络 / 无存储 / 无 I/O）

[Unreleased]: https://gitee.com/evorule/evorule-bundle/compare/v0.2.0...HEAD
[0.2.1]: https://gitee.com/evorule/evorule-bundle/compare/v0.2.0...v0.2.1
[0.2.0]: https://gitee.com/evorule/evorule-bundle/releases/tag/v0.2.0
