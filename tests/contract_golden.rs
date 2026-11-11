//! Distribution contract snapshot tests.
//!
//! Locks the wire shape of `DatasetBundle` against the embedded golden
//! (`evorule_bundle::CONTRACT_GOLDEN`):
//! 1. constructing a bundle from crate types and serializing it must be
//!    byte-identical to the golden (serialization order = struct declaration
//!    order, optional fields skipped when `None`/empty);
//! 2. deserializing the golden must round-trip to the same bundle with a
//!    consistent blake3 content hash;
//! 3. the golden must satisfy the consumption pointers relied upon by
//!    evorule-server `law_host::load_remote` (`/dataset/versioning/current`,
//!    `entries[].entry_id`, `entries[].schema_ref` law_set URI prefix,
//!    `entries[].rule_body`).
//!
//! If any of these tests fail after touching bundle types, the distribution
//! wire contract changed — see `src/contract.rs` change discipline.

use evorule_bundle::{
    BundleAudit, BundleDatasetMeta, BundleEntry, BundleTests, DatasetBundle, EntryKind, LawRef,
    Provenance, TestVerdict, VersionSelection, VersionSelectionMode, Versioning, CONTRACT_GOLDEN,
};

/// The golden bundle, constructed from crate types only (no serde of the
/// fixture itself — construction is the authoritative definition; the fixture
/// is the serialization of this exact value).
fn golden_bundle() -> DatasetBundle {
    DatasetBundle {
        bundle_schema_version: "1.0".into(),
        bundle_id: "bundle-lawset-demo-v2".into(),
        dataset: BundleDatasetMeta {
            dataset_id: "lawset-demo".into(),
            name: "Demo Law Set".into(),
            tenant_id: "tenant-demo".into(),
            instance_id: "instance-demo".into(),
            versioning: Versioning {
                current: "v2".into(),
                chain: vec!["v1".into(), "v2".into()],
            },
            version_selection: Some(VersionSelection {
                mode: VersionSelectionMode::AutoByEffectiveDate,
                pinned_version: None,
                pinned_include_patch: None,
            }),
            law_ref: Some(LawRef {
                document_id: "gov-tax-2023-001".into(),
                law_version: Some("2023".into()),
                effective_from: Some("2024-01-01".into()),
                effective_to: None,
            }),
            view_of: None,
            event_schemas: vec![],
        },
        entries: vec![BundleEntry {
            entry_id: "law-0001".into(),
            entry_kind: EntryKind::Knowledge,
            rule_body: serde_json::json!({
                "id": "newtons_second_law",
                "formula": "F = m * a",
                "symbols": { "F": "force", "m": "mass", "a": "acceleration" },
                "si_units": { "F": "N", "m": "kg", "a": "m s^-2" },
                "domains": ["physical"],
                "max_version_depth": 1,
                "monotone_form": true
            }),
            schema_ref: Some("https://evorule.org/schemas/domain/law_set/law/v1.0.json".into()),
            provenance: Provenance {
                source: "Newton's laws of motion".into(),
                clause: Some("Law II".into()),
                document_id: Some("gov-physics-principia".into()),
                effective_from: Some("2024-01-01".into()),
                effective_to: None,
                last_verified: Some("2026-08-01".into()),
                verified_by: Some("auditor-01".into()),
            },
            domain: "law_set".into(),
            tags: vec![],
            dependencies: vec![],
            knowledge_kind: Some("fact".into()),
            trust_level: Some("human".into()),
            license_ref: None,
            execution_contract: None,
        }],
        data_dependencies: None,
        recipe_snapshot: None,
        tests: BundleTests {
            subset: vec!["sandbox:lawset-demo-laws".into()],
            fixtures: vec![],
            verdict: TestVerdict::Pass,
        },
        audit: BundleAudit {
            exported_at: "2026-11-11T00:00:00Z".into(),
            exported_by: "contract-golden".into(),
            source_version: "v2".into(),
            content_hash: String::new(),
            hash_algo: "blake3".into(),
        },
        publish_signature: None,
    }
}

/// The golden bundle with its blake3 content hash filled in (the export path
/// always emits a hash-covered bundle).
fn sealed_golden_bundle() -> DatasetBundle {
    let mut bundle = golden_bundle();
    bundle.audit.content_hash = bundle.compute_content_hash();
    bundle
}

#[test]
fn serialization_is_byte_identical_to_golden() {
    let golden = serde_json::to_string_pretty(&sealed_golden_bundle()).unwrap();
    assert_eq!(golden, CONTRACT_GOLDEN, "bundle wire shape drifted");
}

#[test]
fn golden_deserializes_and_round_trips() {
    let parsed: DatasetBundle = serde_json::from_str(CONTRACT_GOLDEN).unwrap();
    assert_eq!(parsed, sealed_golden_bundle(), "round-trip mismatch");
    parsed
        .verify_content_hash()
        .expect("golden content hash must be internally consistent");
}

#[test]
fn golden_satisfies_law_host_consumption_pointers() {
    let parsed: serde_json::Value = serde_json::from_str(CONTRACT_GOLDEN).unwrap();
    // evorule-server law_host::load_remote reads exactly these pointers:
    assert_eq!(
        parsed
            .pointer("/dataset/versioning/current")
            .and_then(|v| v.as_str()),
        Some("v2"),
        "dataset.versioning.current must anchor the dataset version"
    );
    let entries = parsed
        .get("entries")
        .and_then(|v| v.as_array())
        .expect("entries must be an array");
    assert!(!entries.is_empty(), "law_host rejects empty entry sets");
    for entry in entries {
        let entry_id = entry.get("entry_id").and_then(|v| v.as_str()).unwrap_or("");
        assert!(!entry_id.is_empty(), "entries[].entry_id must be present");
        let schema_ref = entry
            .get("schema_ref")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            schema_ref.starts_with("https://evorule.org/schemas/domain/law_set/"),
            "entries[].schema_ref must be a law_set domain URI, got `{schema_ref}` (entry {entry_id})"
        );
        assert!(
            entry
                .get("rule_body")
                .map(|v| !v.is_null())
                .unwrap_or(false),
            "entries[].rule_body must carry the zero-translation payload (entry {entry_id})"
        );
    }
}

/// Maintenance entry point: regenerates `fixtures/contract_golden.json` from
/// the authoritative construction above. Run explicitly with
/// `cargo test --test contract_golden -- --ignored regenerate_golden_fixture`,
/// review the diff, and bump the crate version per the change discipline in
/// `src/contract.rs`.
#[test]
#[ignore = "maintenance: overwrites fixtures/contract_golden.json"]
fn regenerate_golden_fixture() {
    let golden = serde_json::to_string_pretty(&sealed_golden_bundle()).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("contract_golden.json");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(&path, golden).unwrap();
}
