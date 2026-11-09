# SSR JSON report schema

The collector emits schema version **3**. It preserves the existing collector,
firmware, system, inventory, research-module, check, inaccessible-resource,
and error fields, and adds three distinct top-level collections:

- `vulnerabilities`: vulnerability findings and their assessments;
- `evidence`: provenance-bearing evidence records;
- `vulnerability_chains`: ordered findings, dependency rationales, and chain
  evidence.

An empty collection is emitted as `[]`. No finding or evidence is fabricated
to populate a report.

## Findings and assessments

Each vulnerability contains its stable ID, title and technical description,
status, affected component and versions, assessment status and detail,
exploitation assessment, evidence/reference/chain IDs, reproducibility, and
limitations. Evidence records are not copied into a finding: `evidence_ids`
links to the top-level evidence collection.

`status` describes the vulnerability conclusion (`CONFIRMED`, `SUSPECT`,
`INCONCLUSIVE`, or `NOT_ACCESSIBLE`). `assessment_status` separately describes
the completeness of the assessment (`COMPLETE`, `PARTIAL`, `INCONCLUSIVE`, or
`NOT_ACCESSIBLE`). An execution error or an inaccessible resource does not
establish that a finding is safe or vulnerable.

`achieved_level`, `potential_level`, and `chain_level` are serialized as
`LEVEL_0` through `LEVEL_3`, or JSON `null` if unknown or not assigned.
`potential_level` includes a rationale when present. Level 4 is rejected by
validation for findings and chains and is never emitted. Missing evidence is
not converted into negative evidence or level 0.

## Evidence and chains

Evidence records retain their ID, control, kind, source, method, summary,
collection time, reproducibility information, target context, limitations,
and demonstrated capabilities. Direct observations and external validations
must include target context and reproducibility details.

Chains retain `ordered_finding_ids`, one `dependency_rationales` entry per
transition, status, exploitation data, evidence IDs, and limitations. A
confirmed chain must reference confirmed findings and satisfy the phase-1
evidence validation rules.

Before serialization, the exporter rejects duplicate or empty IDs, unknown
references, invalid statuses, malformed evidence provenance, invalid chains,
and exploitation levels that fail the phase-1 validators. It does not repair
or downgrade invalid data silently.

## Compatibility and scope

Version 3 is a structural extension of version 2. Existing fields remain
present, but this project has not tested compatibility with external schema-v2
consumers or implemented a report reader/migration path. Consumers should
branch on `schema_version`.

This phase integrates and serializes data models only. USB, IPC, memory, and
known-vulnerability modules remain declarations and do not perform scans.
Report output must not contain secrets, keys, certificates, personal
identifiers, or exploit payloads. The collector remains read-only and does not
access NAND/eMMC or modify system data.
