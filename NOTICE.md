<!--
  Copyright 2026 EvoRule Project
  SPDX-License-Identifier: Apache-2.0
-->

# EvoRule Bundle — 声明

**版权所有 (c) 2026 EvoRule Project**

本 crate（`evorule-bundle`）是 EvoRule 生态的一部分，提供快照包（`DatasetBundle`）共享校验库。

## 协议

| 资产 | 协议 | 说明 |
|---|---|---|
| **代码**（v0.2.1 起） | Apache-2.0 | 详见 [LICENSE](LICENSE) |
| 代码（v0.2.0 历史版本） | AGPL-3.0-or-later | 已发布版本不可撤回，历史版本仍适用原许可 |

Apache-2.0 授予对本 crate 代码的使用权，**不授予 EvoRule 名称与商标的使用权**
（商标说明见 [evorule-system-rules TRADEMARK.md](https://gitee.com/evorule/evorule-system-rules)）。

## 定位

治理侧（evorule-rule）与执行侧（evorule-server）之间解耦的**唯一传输契约**——
快照包类型与 6 项导入校验链的**单一事实来源（SSOT）**，两仓以钉版依赖消费，避免校验口径漂移。

## 设计原则

- 单一事实来源：类型与校验链只在此仓实现一次，治理侧/执行侧共同消费
- 确定性校验：失败显式报错，不静默降级
- 零转译：`entries[].rule_body` 原样可执行，无翻译层
- 裁剪即视图：裁剪 = 原版本视图，不新造版本链

## 联系信息

- **项目**: EvoRule — 反应式执行引擎
- **作者**: EvoRule Project
- **邮箱**: <evorulelab@gmail.com>
- **组织**: [EvoRule Lab](https://gitee.com/evorule)
- **Gitee**: <https://gitee.com/evorule/evorule-bundle>
