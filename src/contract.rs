//! Distribution contract golden snapshot — single source of truth for the
//! `GET /v1/datasets/{id}/bundle` wire shape.
//!
//! `CONTRACT_GOLDEN` is a byte-exact representative minimal law_set
//! `DatasetBundle` (as produced by the governance-side `BundleExporter`
//! export path) embedded into the rlib via `include_str!`. Downstream
//! consumers (evorule-rule CI contract tests, evorule-server law_host mock
//! alignment) read the same embedded bytes — no fixture files on disk, no
//! copy drift across repos.
//!
//! Change discipline: any serde-visible change to the bundle types (field
//! rename, new field, changed skip rule) breaks the snapshot test in
//! `tests/contract_golden.rs` on purpose — that is the distribution contract
//! gate. To evolve the contract intentionally, update the golden via the
//! `#[ignore]`d `regenerate_golden_fixture` test, review the diff, and bump
//! the crate version.

/// Embedded distribution contract golden (pretty JSON, no trailing newline).
pub const CONTRACT_GOLDEN: &str = include_str!("../fixtures/contract_golden.json");
