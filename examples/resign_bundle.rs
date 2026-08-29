// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 EvoRule Project
//! 改签快照包（一次性验收辅助工具）
//!
//! 用途：T6 端到端验收——治理侧 ds-yuanze-01 的 bundle 缺少 `law_ref`/`version_selection`
//! （治理 API 暂无法设置这两字段，见验收记录），在执行侧 import 前补齐运行配置元数据并
//! 用 crate 自身 canonical 哈希重签（`compute_content_hash`），保证与 Rust 序列化完全一致。
//!
//! 用法：`cargo run --example resign_bundle -- <input.json> <output.json>`
//!   读取 DatasetBundle JSON → 重算 content_hash → 写入 output.json。
//!   输入内 `audit.content_hash` 字段被忽略（重签覆盖）。

use std::process::ExitCode;

use evorule_bundle::DatasetBundle;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(input), Some(output)) = (args.next(), args.next()) else {
        eprintln!("用法: resign_bundle <input.json> <output.json>");
        return ExitCode::FAILURE;
    };

    let raw = match std::fs::read_to_string(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("读取输入失败 {input}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut bundle: DatasetBundle = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("解析快照包失败 {input}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let hash = bundle.compute_content_hash();
    bundle.audit.content_hash = hash.clone();
    match serde_json::to_writer_pretty(std::fs::File::create(&output).unwrap(), &bundle) {
        Ok(()) => {
            println!("已重签 {output}");
            println!("  bundle_id      = {}", bundle.bundle_id);
            println!("  dataset_id     = {}", bundle.dataset.dataset_id);
            println!("  source_version = {}", bundle.audit.source_version);
            println!("  entries        = {}", bundle.entries.len());
            println!("  content_hash   = {hash}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("写入输出失败 {output}: {e}");
            ExitCode::FAILURE
        }
    }
}
