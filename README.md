# lava-drift

Typed drift detector for lava architectures. L2 of the lava-suite.

```text
DriftDetector::scan(spec, bindings)
  │
  ├─ PlannerBackend::plan(spec, current_state)  ← pluggable seam
  ├─ classify each non-NoOp ResourceChange
  │       into DriftedField { address, attribute, observed, declared, severity }
  ▼
DriftReport { spec_hash, scanned_at, drifted_fields, max_severity }
```

## Abstractions

| Trait / type | Purpose |
|---|---|
| `PlannerBackend` | Pluggable seam to magma (production) or test mock |
| `MockPlanner` | Caller-supplied findings for unit tests |
| `DriftDetector<B>` | Composes backend + classifier |
| `Severity` | `Cosmetic < Functional < Critical` |
| `DriftedField` | One drifted field with typed severity |
| `DriftReport` | Aggregate; `clean()`, `at_or_above(Severity)`, `max_severity` |

## Severity classification

| ChangeKind | Default severity |
|---|---|
| `Delete` | `Critical` |
| `Replace` | `Critical` |
| `Create` | `Functional` |
| `Update` on `tags.*` | `Cosmetic` |
| `Update` on anything else | `Functional` |
| `NoOp` | filtered out |

`DriftDetector::with_cosmetic_prefixes(vec)` overrides the
attribute-prefix list that demotes Functional → Cosmetic.

## Use

```rust
let detector = DriftDetector::new(my_planner);
let report = detector.scan(spec_source, &bindings)?;
if let Some(severity) = report.max_severity {
    // route through AnomalyController (L4)
}
```

Production: `my_planner` = magma-backed planner that calls
`magma-lava::synthesize_*` → `magma::config::parse` →
`magma::plan::plan`. Wired into lava-operator at L3.

## Tests

13 unit tests cover severity ordering, classifier rules (Delete/
Replace/Create/Update-tags/Update-non-tags/NoOp), `at_or_above`,
`max_severity`, custom prefixes, serde round-trip, spec-hash
sensitivity to source.
