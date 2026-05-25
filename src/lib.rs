//! lava-drift — typed drift detector for lava architectures.
//!
//! ## Shape
//!
//! ```text
//! DriftDetector::scan(spec)
//!   │
//!   ├─ PlannerBackend::plan(spec, current_state)  ← pluggable
//!   │                                                seam
//!   ├─ classify each non-NoOp ResourceChange
//!   │       into DriftedField { address, attribute,
//!   │                          observed, declared, severity }
//!   ▼
//! DriftReport { spec_hash, scanned_at, drifted_fields, severity }
//! ```
//!
//! ## Solid abstractions
//!
//! - [`PlannerBackend`] — the only seam to magma. Production wires
//!   in `magma-lava + magma::plan::plan`; tests use [`MockPlanner`]
//!   to drive arbitrary `DriftFinding`s without spinning up magma.
//! - [`DriftDetector`] — composes a `PlannerBackend` with the
//!   classifier; one `scan(spec)` call returns a typed `DriftReport`.
//! - [`Severity`] — the cross-suite typed classification: Cosmetic /
//!   Functional / Critical. Wired into Anomaly routing at L4.
//! - [`DriftReport`] — typed; serializes cleanly to JSON for
//!   OutcomeChain payloads + CRD status.

#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use lava_outcome_chain::ContentHash;

// ── Severity ───────────────────────────────────────────────────────

/// Drift severity tier. Used by L4's AnomalyController to pick the
/// remediation policy. Default ordering: `Cosmetic < Functional < Critical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Drift exists but doesn't break promises (e.g. label change).
    Cosmetic,
    /// Drift would change behavior on next apply (e.g. attribute
    /// change). Default for any non-tag Update.
    Functional,
    /// Drift would delete or recreate a resource (e.g. force-new
    /// or Delete). Default for any Delete or replace operation.
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cosmetic => "cosmetic",
            Self::Functional => "functional",
            Self::Critical => "critical",
        }
    }
}

// ── DriftedField + DriftReport ────────────────────────────────────

/// One field that drifted between declared + observed state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftedField {
    /// Terraform-style resource address: `<type_id>.<name>`.
    pub address: String,
    /// Attribute path inside the resource (e.g. `cidr_block` or
    /// `tags.Environment`). `*` when the entire resource is missing
    /// or extra.
    pub attribute: String,
    /// String form of the observed value (or `null`).
    pub observed: Option<String>,
    /// String form of the declared value (or `null`).
    pub declared: Option<String>,
    pub severity: Severity,
}

impl DriftedField {
    #[must_use]
    pub fn new(address: impl Into<String>, attribute: impl Into<String>, severity: Severity) -> Self {
        Self {
            address: address.into(),
            attribute: attribute.into(),
            observed: None,
            declared: None,
            severity,
        }
    }

    #[must_use]
    pub fn with_values(mut self, observed: Option<String>, declared: Option<String>) -> Self {
        self.observed = observed;
        self.declared = declared;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftReport {
    pub spec_hash: ContentHash,
    pub scanned_at: DateTime<Utc>,
    pub drifted_fields: Vec<DriftedField>,
    /// Maximum severity across drifted fields. `None` when the report
    /// is clean.
    pub max_severity: Option<Severity>,
}

impl DriftReport {
    /// Is the architecture drift-free?
    #[must_use]
    pub fn clean(&self) -> bool {
        self.drifted_fields.is_empty()
    }

    /// Total drifted fields.
    #[must_use]
    pub fn count(&self) -> usize {
        self.drifted_fields.len()
    }

    /// Filter to fields at or above the supplied severity. Used by
    /// AnomalyController to route Critical drift to Escalate even
    /// when Cosmetic drift is also present.
    #[must_use]
    pub fn at_or_above(&self, min: Severity) -> Vec<&DriftedField> {
        self.drifted_fields
            .iter()
            .filter(|f| f.severity >= min)
            .collect()
    }
}

// ── PlannerBackend trait + impls ──────────────────────────────────

/// A raw drift-detection finding from a planner backend. Lower-level
/// than [`DriftedField`] — the detector classifies severity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftFinding {
    pub address: String,
    pub attribute: String,
    /// Typed change-kind from the planner (`create` | `update` |
    /// `delete` | `replace` | `no_op`).
    pub change: ChangeKind,
    pub observed: Option<String>,
    pub declared: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    Create,
    Update,
    Delete,
    Replace,
    NoOp,
}

/// The pluggable planner trait. Production impl: magma-backed
/// re-plan via magma-lava. Test impl: [`MockPlanner`].
pub trait PlannerBackend {
    /// Re-plan the supplied .tlisp source against current state +
    /// return the raw drift findings.
    ///
    /// # Errors
    /// Surfaces backend-specific failures as [`PlannerError`].
    fn plan(
        &self,
        spec_source: &str,
        bindings: &IndexMap<String, String>,
    ) -> Result<Vec<DriftFinding>, PlannerError>;
}

#[derive(Debug, Error)]
pub enum PlannerError {
    #[error("synthesize: {0}")]
    Synthesize(String),
    #[error("plan: {0}")]
    Plan(String),
    #[error("backend: {0}")]
    Backend(String),
}

/// In-memory planner with caller-supplied findings. Drives detector
/// unit tests without an embedded magma engine.
pub struct MockPlanner {
    pub findings: Vec<DriftFinding>,
}

impl MockPlanner {
    #[must_use]
    pub fn new(findings: Vec<DriftFinding>) -> Self {
        Self { findings }
    }
    #[must_use]
    pub fn empty() -> Self {
        Self { findings: vec![] }
    }
}

impl PlannerBackend for MockPlanner {
    fn plan(
        &self,
        _spec_source: &str,
        _bindings: &IndexMap<String, String>,
    ) -> Result<Vec<DriftFinding>, PlannerError> {
        Ok(self.findings.clone())
    }
}

// ── DriftDetector ──────────────────────────────────────────────────

/// The detector composes a [`PlannerBackend`] with severity
/// classification. Holds no IaC state itself — the only mutable
/// state lives in the backend.
pub struct DriftDetector<B: PlannerBackend> {
    backend: B,
    /// Attribute-name suffixes that demote a Functional change to
    /// Cosmetic. Defaults to `["tags."]`.
    pub cosmetic_attribute_prefixes: Vec<String>,
}

impl<B: PlannerBackend> DriftDetector<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            cosmetic_attribute_prefixes: vec!["tags.".to_string()],
        }
    }

    /// Override the cosmetic-attribute classifier. Empty vec means
    /// no attribute is downgraded.
    #[must_use]
    pub fn with_cosmetic_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.cosmetic_attribute_prefixes = prefixes;
        self
    }

    /// Scan one architecture. Returns a typed [`DriftReport`].
    ///
    /// # Errors
    /// Bubbles up [`PlannerError`] from the backend.
    pub fn scan(
        &self,
        spec_source: &str,
        bindings: &IndexMap<String, String>,
    ) -> Result<DriftReport, PlannerError> {
        let findings = self.backend.plan(spec_source, bindings)?;
        let drifted_fields: Vec<DriftedField> = findings
            .into_iter()
            .filter(|f| !matches!(f.change, ChangeKind::NoOp))
            .map(|f| self.classify(f))
            .collect();
        let max_severity = drifted_fields.iter().map(|f| f.severity).max();
        let spec_hash = ContentHash::of(spec_source.as_bytes());
        Ok(DriftReport {
            spec_hash,
            scanned_at: Utc::now(),
            drifted_fields,
            max_severity,
        })
    }

    fn classify(&self, f: DriftFinding) -> DriftedField {
        let severity = match f.change {
            ChangeKind::Delete | ChangeKind::Replace => Severity::Critical,
            ChangeKind::Create => Severity::Functional,
            ChangeKind::Update => {
                if self
                    .cosmetic_attribute_prefixes
                    .iter()
                    .any(|p| f.attribute.starts_with(p))
                {
                    Severity::Cosmetic
                } else {
                    Severity::Functional
                }
            }
            ChangeKind::NoOp => Severity::Cosmetic, // unreachable post-filter
        };
        DriftedField {
            address: f.address,
            attribute: f.attribute,
            observed: f.observed,
            declared: f.declared,
            severity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: ChangeKind, attr: &str) -> DriftFinding {
        DriftFinding {
            address: "aws_vpc.main".into(),
            attribute: attr.into(),
            change: kind,
            observed: Some("a".into()),
            declared: Some("b".into()),
        }
    }

    #[test]
    fn severity_orders_cosmetic_lt_functional_lt_critical() {
        assert!(Severity::Cosmetic < Severity::Functional);
        assert!(Severity::Functional < Severity::Critical);
    }

    #[test]
    fn scan_returns_clean_report_when_planner_finds_nothing() {
        let detector = DriftDetector::new(MockPlanner::empty());
        let report = detector.scan("(deflava-architecture x)", &IndexMap::new()).unwrap();
        assert!(report.clean());
        assert_eq!(report.max_severity, None);
    }

    #[test]
    fn scan_filters_noop_findings() {
        let detector = DriftDetector::new(MockPlanner::new(vec![
            finding(ChangeKind::NoOp, "cidr_block"),
            finding(ChangeKind::NoOp, "tags.Name"),
        ]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert!(report.clean());
    }

    #[test]
    fn scan_classifies_delete_as_critical() {
        let detector = DriftDetector::new(MockPlanner::new(vec![finding(
            ChangeKind::Delete,
            "*",
        )]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.count(), 1);
        assert_eq!(report.max_severity, Some(Severity::Critical));
    }

    #[test]
    fn scan_classifies_replace_as_critical() {
        let detector = DriftDetector::new(MockPlanner::new(vec![finding(
            ChangeKind::Replace,
            "cidr_block",
        )]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.max_severity, Some(Severity::Critical));
    }

    #[test]
    fn scan_classifies_create_as_functional() {
        let detector = DriftDetector::new(MockPlanner::new(vec![finding(
            ChangeKind::Create,
            "*",
        )]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.max_severity, Some(Severity::Functional));
    }

    #[test]
    fn scan_classifies_update_of_tags_as_cosmetic_by_default() {
        let detector = DriftDetector::new(MockPlanner::new(vec![finding(
            ChangeKind::Update,
            "tags.Environment",
        )]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.max_severity, Some(Severity::Cosmetic));
    }

    #[test]
    fn scan_classifies_update_of_cidr_as_functional() {
        let detector = DriftDetector::new(MockPlanner::new(vec![finding(
            ChangeKind::Update,
            "cidr_block",
        )]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.max_severity, Some(Severity::Functional));
    }

    #[test]
    fn at_or_above_filters_correctly() {
        let detector = DriftDetector::new(MockPlanner::new(vec![
            finding(ChangeKind::Update, "tags.X"),
            finding(ChangeKind::Update, "cidr_block"),
            finding(ChangeKind::Delete, "*"),
        ]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.at_or_above(Severity::Cosmetic).len(), 3);
        assert_eq!(report.at_or_above(Severity::Functional).len(), 2);
        assert_eq!(report.at_or_above(Severity::Critical).len(), 1);
    }

    #[test]
    fn max_severity_picks_highest_across_fields() {
        let detector = DriftDetector::new(MockPlanner::new(vec![
            finding(ChangeKind::Update, "tags.X"), // Cosmetic
            finding(ChangeKind::Delete, "*"),       // Critical
            finding(ChangeKind::Update, "cidr"),    // Functional
        ]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.max_severity, Some(Severity::Critical));
    }

    #[test]
    fn custom_cosmetic_prefixes_override_default() {
        let detector = DriftDetector::new(MockPlanner::new(vec![finding(
            ChangeKind::Update,
            "labels.team",
        )]))
        .with_cosmetic_prefixes(vec!["labels.".into()]);
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        assert_eq!(report.max_severity, Some(Severity::Cosmetic));
    }

    #[test]
    fn drift_report_round_trips_through_serde() {
        let detector = DriftDetector::new(MockPlanner::new(vec![finding(
            ChangeKind::Delete,
            "*",
        )]));
        let report = detector.scan("src", &IndexMap::new()).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: DriftReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    #[test]
    fn spec_hash_changes_with_source() {
        let detector = DriftDetector::new(MockPlanner::empty());
        let r1 = detector.scan("source-v1", &IndexMap::new()).unwrap();
        let r2 = detector.scan("source-v2", &IndexMap::new()).unwrap();
        assert_ne!(r1.spec_hash, r2.spec_hash);
    }
}
