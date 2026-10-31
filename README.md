<!--
  Copyright 2026 EvoRule Project

  SPDX-License-Identifier: AGPL-3.0-or-later

  This file is part of EvoRule. Code is licensed under AGPL-3.0-or-later;
  see the License section below for dual-license and historical notes
  (v0.2.1–v0.3.0 briefly used Apache-2.0, reverted to AGPL-3.0-or-later as of v0.3.1).
-->

# evorule-bundle

Snapshot sharing and verification crate: the single transfer contract between the governance side (evorule-rule) and the execution side (evorule-server) — a pure library with no binary, no service, and no I/O.

[![CI][badge-ci]][ci-link]
[![crates.io][badge-crate]][crate-link]
[![docs.rs][badge-docs]][docs-link]
[![License: AGPL-3.0-or-later][badge-license]][license-link]

**License**: [AGPL-3.0-or-later](LICENSE) with [dual licensing](DUAL_LICENSE.md)

Part of the [evorule](https://github.com/evorule/evorule) ecosystem. The `DatasetBundle` snapshot type, the six-item import validation chain, the trimmer, and the version / dependency / provenance models live here as a single source of truth: when both sides held their own copies, validation verdicts and serialization contracts drifted. Here any semantic change takes effect once, and both consumers depend on it pinned by version.

## Features

- **`DatasetBundle` (snapshot package)** — the only transfer form between asset governance and execution: a single-file, read-only JSON artifact
- **Six-item validation chain** (`BundleImporter::validate`; explicit errors, never silent degradation): schema version → tamper-evident content hash (BLAKE3 via evorule-hash, `blake3:`-prefixed) → version-chain integrity → symbol three-way agreement (`rule_body` ≡ entry dependencies ≡ data dependencies) → version resolution (pinned / auto by effective date) → gate-one evidence (verdict = pass before import)
- **Trimming** (`BundleTrimmer`) — a trim is a view of the original version; it never mints a new version chain, and dependency declarations shrink with the trim
- **Model SSOT** — versioning (`Version` / `Versioning` / `VersionSelection` / `LawRef`), resolution (`VersionResolver`), dependencies (`DataDependencies` / `SourceBinding` / `IoContract` / `InputDecl`), provenance (`Provenance`), and symbol extraction (`io_services_from_rule_body`)
- **Zero translation** — `entries[].rule_body` ships as-is: it is exactly the evorule-server executable rule JSON

> Export (`BundleExporter`) depends on governance-side types and stays in evorule-rule; this crate carries only the snapshot package's self-contained validation.

## Installation

```toml
[dependencies]
evorule-bundle = "0.6"
```

For cross-repo joint development, override the registry line with a local path (the same pattern the server uses for its pinned core crates):

```toml
[patch.crates-io]
evorule-bundle = { path = "../evorule-bundle" }
```

## Usage

```rust
use evorule_bundle::{BundleImporter, DatasetBundle};

let bundle: DatasetBundle = serde_json::from_str(&bundle_json)?;

// The host injects the domain schema resolver (Knowledge entries are validated
// against the resolved schema); an unregistered schema_ref is rejected fail-fast.
let registry: std::collections::HashMap<String, serde_json::Value> = load_registry();
let result = BundleImporter::validate(&bundle, &|uri| registry.get(uri).cloned())?;

println!("{result:?}"); // bundle_id, resolved_version, entry_count, verdict
```

## Versioning & Compatibility

- `validate` is consumed by both evorule-rule and evorule-server; any change to validation semantics is a breaking change and ships as a MAJOR release, with both consumers upgrading in lockstep
- Consumers depend on a pinned version requirement; the latest published release is tracked by the crates.io badge above

## Documentation

API reference: [docs.rs/evorule-bundle](https://docs.rs/evorule-bundle)

## License

**AGPL-3.0-or-later** (unified across the ecosystem). Dual licensing applies: closed-source use — see [DUAL_LICENSE.md](DUAL_LICENSE.md), [FREE_COMMERCIAL_LICENSE.md](FREE_COMMERCIAL_LICENSE.md) (free waiver for eligible entities), or [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). The constitution `core_eval.json` is CC0-1.0. Commercial inquiries: <evorulelab@gmail.com>.

> History: v0.2.0 shipped as AGPL, v0.2.1–v0.3.0 briefly as Apache-2.0; from v0.3.1 the crate is back on AGPL-3.0-or-later. Already-published versions keep their original license (published crates.io versions cannot be relicensed) — consumers pinning old versions should check the license of the pinned release.

This license grants the right to use the code, not the EvoRule name or trademark.

[badge-ci]: https://github.com/evorule/evorule-bundle/actions/workflows/ci.yml/badge.svg
[ci-link]: https://github.com/evorule/evorule-bundle/actions/workflows/ci.yml
[badge-crate]: https://img.shields.io/crates/v/evorule-bundle?style=flat-square
[crate-link]: https://crates.io/crates/evorule-bundle
[badge-docs]: https://img.shields.io/docsrs/evorule-bundle?style=flat-square
[docs-link]: https://docs.rs/evorule-bundle
[badge-license]: https://img.shields.io/badge/license-AGPL--3.0--or--later-blue?style=flat-square
[license-link]: LICENSE
