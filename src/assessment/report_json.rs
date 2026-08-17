//! Machine-readable view of a `MultitenancyReport`.
//!
//! This is a *view*, not the internal model. The assessment types are generic
//! over `AssessableResource`, and their operations live in a
//! `HashMap<R::Operation, _>` — serialising those directly would mean adding a
//! `Serialize` bound to the trait, deriving it on every resource and operation
//! enum, and still hitting the fact that JSON object keys must be strings.
//! Every resource and operation already implements `Display`, so the view
//! converts through that and stays entirely additive: nothing in the assessment
//! path changes shape to accommodate it.
//!
//! Why it exists: the kubectl-mtb comparison has to join our per-property
//! verdicts against that tool's per-benchmark verdicts. Doing that by scraping
//! the terminal table is how transcription errors reached Table I of the first
//! submission.

use serde::Serialize;

use super::{
    AssessableResource, AutonomyRatio, ControlPlaneAutonomyLevels, IsolationLevel,
    MultitenancyReport, ResourceAssessment, SubsystemReport,
};

/// Bumped when the shape changes in a way a reader must notice.
const SCHEMA_VERSION: u32 = 1;

/// An isolation level, flattened so a consumer can group on `level` without
/// unwrapping a variant.
///
/// `Soft` is the only level carrying a reason, and it is the level that matters
/// most in the comparison: the operation was blocked, but in a way that reveals
/// the shared environment. A binary pass/fail tool records that as a pass.
#[derive(Debug, Clone, Serialize)]
pub struct IsolationJson {
    pub level: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&IsolationLevel> for IsolationJson {
    fn from(level: &IsolationLevel) -> Self {
        match level {
            IsolationLevel::Hard => Self {
                level: "Hard",
                reason: None,
            },
            IsolationLevel::Soft(reason) => Self {
                level: "Soft",
                reason: Some(reason.clone()),
            },
            IsolationLevel::None => Self {
                level: "None",
                reason: None,
            },
            IsolationLevel::Unknown => Self {
                level: "Unknown",
                reason: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AutonomyJson {
    pub allowed: usize,
    pub total: usize,
    /// Precomputed so consumers do not each reimplement the zero-total case.
    pub percentage: f64,
}

impl From<&AutonomyRatio> for AutonomyJson {
    fn from(ratio: &AutonomyRatio) -> Self {
        Self {
            allowed: ratio.allowed,
            total: ratio.total,
            percentage: if ratio.total == 0 {
                0.0
            } else {
                ratio.allowed as f64 / ratio.total as f64 * 100.0
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OperationJson {
    pub operation: String,
    pub isolation: IsolationJson,
    pub autonomy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceJson {
    pub resource: String,
    pub overall_isolation: IsolationJson,
    /// A list rather than an object, sorted by operation name.
    ///
    /// The source is a `HashMap`, whose iteration order varies between runs. An
    /// unsorted list would make two reports of an unchanged cluster diff as if
    /// something had moved.
    pub operations: Vec<OperationJson>,
}

impl<R: AssessableResource> From<&ResourceAssessment<R>> for ResourceJson {
    fn from(assessment: &ResourceAssessment<R>) -> Self {
        let mut operations: Vec<OperationJson> = assessment
            .operations
            .iter()
            .map(|(operation, result)| OperationJson {
                operation: operation.to_string(),
                isolation: (&result.isolation).into(),
                autonomy: result.autonomy,
                details: result.details.clone(),
            })
            .collect();
        operations.sort_by(|a, b| a.operation.cmp(&b.operation));

        Self {
            resource: assessment.resource.to_string(),
            overall_isolation: (&assessment.overall_isolation).into(),
            operations,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SubsystemJson {
    pub name: String,
    pub isolation: IsolationJson,
    pub autonomy: AutonomyJson,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub resources: Vec<ResourceJson>,
}

impl<R: AssessableResource> From<&SubsystemReport<R>> for SubsystemJson {
    fn from(report: &SubsystemReport<R>) -> Self {
        let mut resources: Vec<ResourceJson> =
            report.assessments.iter().map(ResourceJson::from).collect();
        resources.sort_by(|a, b| a.resource.cmp(&b.resource));

        Self {
            name: report.name.clone(),
            isolation: (&report.isolation_level).into(),
            autonomy: (&report.autonomy_ratio).into(),
            warnings: report.warnings.clone(),
            resources,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlPlaneAutonomyJson {
    pub workload: AutonomyJson,
    pub scope: AutonomyJson,
    pub infrastructure: AutonomyJson,
    pub cluster: AutonomyJson,
}

impl From<&ControlPlaneAutonomyLevels> for ControlPlaneAutonomyJson {
    fn from(levels: &ControlPlaneAutonomyLevels) -> Self {
        Self {
            workload: (&levels.workload).into(),
            scope: (&levels.scope).into(),
            infrastructure: (&levels.infrastructure).into(),
            cluster: (&levels.cluster).into(),
        }
    }
}

/// A complete isolation assessment, with the provenance needed to trace it.
///
/// The header mirrors the fairness run manifest deliberately: a result set is
/// only comparable with another if you can tell which binary and which solution
/// produced each one.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReportJson {
    pub schema_version: u32,
    pub tool_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    pub started_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution_label: Option<String>,
    pub overall_isolation: IsolationJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_plane_autonomy: Option<ControlPlaneAutonomyJson>,
    pub subsystems: Vec<SubsystemJson>,
}

impl VerifyReportJson {
    pub fn new(
        report: &MultitenancyReport,
        solution_label: Option<String>,
        started_at_utc: String,
        git_commit: Option<String>,
    ) -> Self {
        // Subsystems that were not requested are absent rather than empty: an
        // empty subsystem and a skipped one mean different things, and the
        // analysis must not read "no findings" as "nothing to find".
        let mut subsystems = Vec::new();
        if let Some(cp) = &report.control_plane {
            subsystems.push(SubsystemJson::from(cp));
        }
        if let Some(storage) = &report.storage {
            subsystems.push(SubsystemJson::from(storage));
        }
        if let Some(network) = &report.network {
            subsystems.push(SubsystemJson::from(network));
        }
        if let Some(workload) = &report.workload {
            subsystems.push(SubsystemJson::from(workload));
        }

        Self {
            schema_version: SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit,
            started_at_utc,
            solution_label,
            overall_isolation: (&report.overall_isolation()).into(),
            control_plane_autonomy: report
                .control_plane_autonomy_levels
                .as_ref()
                .map(ControlPlaneAutonomyJson::from),
            subsystems,
        }
    }
}

/// One assessable property: a subsystem, a resource, and an operation on it.
#[derive(Debug, Clone, Serialize)]
pub struct PropertyJson {
    pub subsystem: &'static str,
    pub resource: String,
    pub operation: String,
}

/// Every property this tool can assess, without needing a cluster.
///
/// Generated from `AssessableResource::all()` and `applicable_operations()`, so
/// it cannot drift from what the assessors actually do. Two uses: the paper
/// quotes a coverage count that should be derived rather than asserted, and the
/// kubectl-mtb mapping has to name properties by the exact strings the JSON
/// report emits — transcribing those by hand is how a mapping silently stops
/// matching anything.
#[derive(Debug, Clone, Serialize)]
pub struct PropertyInventoryJson {
    pub schema_version: u32,
    pub tool_version: String,
    pub property_count: usize,
    pub properties: Vec<PropertyJson>,
}

fn properties_of<R: AssessableResource>(subsystem: &'static str) -> Vec<PropertyJson> {
    let mut properties = Vec::new();
    for resource in R::all() {
        for operation in resource.applicable_operations() {
            properties.push(PropertyJson {
                subsystem,
                resource: resource.to_string(),
                operation: operation.to_string(),
            });
        }
    }
    properties
}

impl PropertyInventoryJson {
    pub fn build() -> Self {
        use crate::assessment::{
            ControlPlaneResource, NetworkResource, StorageResource, WorkloadResource,
        };

        let mut properties = Vec::new();
        properties.extend(properties_of::<ControlPlaneResource>("control_plane"));
        properties.extend(properties_of::<StorageResource>("storage"));
        properties.extend(properties_of::<NetworkResource>("network"));
        properties.extend(properties_of::<WorkloadResource>("workload"));

        Self {
            schema_version: SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            property_count: properties.len(),
            properties,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::{OperationAssessment, StorageOperation, StorageResource};
    use std::collections::HashMap;

    fn storage_report(
        operations: Vec<(StorageOperation, IsolationLevel, bool)>,
    ) -> MultitenancyReport {
        let mut map = HashMap::new();
        for (operation, isolation, autonomy) in operations {
            map.insert(
                operation,
                OperationAssessment {
                    isolation,
                    autonomy,
                    details: Some("probe detail".into()),
                },
            );
        }
        let assessment = ResourceAssessment {
            resource: StorageResource::Volume,
            overall_isolation: IsolationLevel::Soft("shared backend".into()),
            operations: map,
        };
        MultitenancyReport {
            control_plane: None,
            control_plane_autonomy_levels: None,
            storage: Some(SubsystemReport {
                name: "Storage".into(),
                autonomy_ratio: SubsystemReport::calculate_autonomy_ratio(std::slice::from_ref(
                    &assessment,
                )),
                assessments: vec![assessment],
                isolation_level: IsolationLevel::Soft("shared backend".into()),
                warnings: vec![],
            }),
            network: None,
            workload: None,
        }
    }

    #[test]
    fn soft_isolation_carries_its_reason_as_a_field() {
        // The comparison groups on `level`; a consumer must not have to parse a
        // variant name out of an enum tag to do that, and the reason must not be
        // lost, because it is what distinguishes Soft from Hard.
        let report = storage_report(vec![(
            StorageOperation::UseHostPath,
            IsolationLevel::Soft("Forbidden".into()),
            false,
        )]);
        let json = VerifyReportJson::new(&report, Some("capsule".into()), "t".into(), None);
        let value = serde_json::to_value(&json).unwrap();

        let operation = &value["subsystems"][0]["resources"][0]["operations"][0];
        assert_eq!(operation["isolation"]["level"], "Soft");
        assert_eq!(operation["isolation"]["reason"], "Forbidden");
    }

    #[test]
    fn levels_without_a_reason_omit_the_field_entirely() {
        let report = storage_report(vec![(
            StorageOperation::UseHostPath,
            IsolationLevel::Hard,
            false,
        )]);
        let json = VerifyReportJson::new(&report, None, "t".into(), None);
        let value = serde_json::to_value(&json).unwrap();

        let isolation = &value["subsystems"][0]["resources"][0]["operations"][0]["isolation"];
        assert_eq!(isolation["level"], "Hard");
        assert!(isolation.get("reason").is_none());
        // An absent solution label must be absent, not the string "null": the
        // analysis keys on it.
        assert!(value.get("solution_label").is_none());
    }

    #[test]
    fn operations_are_ordered_so_two_runs_can_be_diffed() {
        // The source is a HashMap. Without the sort, two assessments of an
        // unchanged cluster would diff as though something had moved.
        let report = storage_report(vec![
            (StorageOperation::UseHostPath, IsolationLevel::Hard, false),
            (
                StorageOperation::CreateAndMountVolume,
                IsolationLevel::None,
                true,
            ),
            (
                StorageOperation::CreateAndMountVolumeWithRetainPolicy,
                IsolationLevel::Hard,
                false,
            ),
        ]);
        let json = VerifyReportJson::new(&report, None, "t".into(), None);
        let value = serde_json::to_value(&json).unwrap();

        let names: Vec<String> = value["subsystems"][0]["resources"][0]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| op["operation"].as_str().unwrap().to_string())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            names, sorted,
            "operations must be emitted in a stable order"
        );
    }

    #[test]
    fn subsystems_that_did_not_run_are_absent_not_empty() {
        // "Skipped" and "assessed, found nothing" are different claims, and the
        // comparison must not read the first as the second.
        let report = storage_report(vec![(
            StorageOperation::UseHostPath,
            IsolationLevel::Hard,
            false,
        )]);
        let json = VerifyReportJson::new(&report, None, "t".into(), None);
        let value = serde_json::to_value(&json).unwrap();

        let names: Vec<&str> = value["subsystems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["Storage"]);
        assert!(value.get("control_plane_autonomy").is_none());
    }

    #[test]
    fn property_inventory_covers_every_subsystem_and_is_not_empty() {
        // The paper quotes a coverage count and the MTB mapping keys on these
        // exact strings, so both must come from here rather than from a hand
        // count that can drift as resources are added.
        let inventory = PropertyInventoryJson::build();
        assert_eq!(inventory.property_count, inventory.properties.len());
        assert!(
            inventory.property_count > 100,
            "expected the full property space"
        );

        let subsystems: std::collections::BTreeSet<&str> =
            inventory.properties.iter().map(|p| p.subsystem).collect();
        assert_eq!(
            subsystems,
            ["control_plane", "network", "storage", "workload"]
                .into_iter()
                .collect()
        );

        // Display strings are the join key against mtb_mapping.yaml. An empty
        // one would match nothing and produce a silently empty comparison.
        assert!(inventory
            .properties
            .iter()
            .all(|p| !p.resource.is_empty() && !p.operation.is_empty()));
    }

    #[test]
    fn autonomy_percentage_is_computed_and_survives_a_zero_total() {
        let report = storage_report(vec![
            (StorageOperation::UseHostPath, IsolationLevel::Hard, true),
            (
                StorageOperation::CreateAndMountVolume,
                IsolationLevel::Hard,
                false,
            ),
        ]);
        let json = VerifyReportJson::new(&report, None, "t".into(), None);
        let value = serde_json::to_value(&json).unwrap();
        assert_eq!(value["subsystems"][0]["autonomy"]["allowed"], 1);
        assert_eq!(value["subsystems"][0]["autonomy"]["total"], 2);
        assert_eq!(value["subsystems"][0]["autonomy"]["percentage"], 50.0);

        let empty = AutonomyJson::from(&AutonomyRatio::default());
        assert_eq!(empty.percentage, 0.0);
    }
}
