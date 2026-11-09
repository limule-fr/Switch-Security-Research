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
`LEVEL_0` through `LEVEL_4`, or JSON `null` if unknown or not assigned.
`potential_level` includes a rationale when present. Level 4 is emitted only
when the context and evidence requirements in
[`EXPLOITATION_LEVELS.md`](EXPLOITATION_LEVELS.md) pass validation. Missing
evidence is not converted into negative evidence or level 0.

Level-4 context records the initial environment and its evidence IDs, console
model, hardware revision, exact firmware, prerequisites, execution mode,
reproduction description, and independent-validation status. Modes distinguish
`TEMPORARY_LOAD`, `NON_PERSISTENT_BOOT`, and `PERSISTENT_INSTALLATION`. These
are records of external evidence only; the collector never performs those
operations.

## Environment and file inventory

`runtime_environment` includes `STOCK_CONFIRMED`, `CFW_DETECTED`, or
`MODIFIED_OR_UNKNOWN`, qualitative confidence, signal source, detail,
limitations, and evidence IDs. The Horizon adapter can report `CFW_DETECTED`
only from a positive `hosversionIsAtmosphere()` result. A negative result is
`MODIFIED_OR_UNKNOWN`, not stock. Stock confirmation requires linked direct or
external evidence; it cannot be inferred from absent SD markers. Component
provenance is one of `NINTENDO`, `ATMOSPHERE`, `HOMEBREW`, `THIRD_PARTY`, or
`UNKNOWN`; the collector uses `UNKNOWN` where it cannot establish origin.

The inventory adds `root_status` (`ABSENT`, `PRESENT_EMPTY`,
`PRESENT_NONEMPTY`, `PARTIALLY_ACCESSIBLE`, or `NOT_ACCESSIBLE`) and per-file
modification time when available. The only static format validator currently
implemented recognizes NRO and checks its fixed header and segment ranges.
Other formats are reported as unknown/inconclusive; these checks do not detect
malware or prove a file safe.

SHA-256 reference manifests remain local, user-supplied inputs. The report
records the attempted source path. The current manifest format has no
authenticated provenance or version metadata, so its version serializes as
`null`; a match or mismatch is not a security verdict.

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

Version 3 is a structural extension of version 2. The environment and
file-analysis properties described here are additive v3 fields; existing
fields remain present. This project has not tested compatibility with
external schema-v2 consumers or implemented a report reader/migration path.
Consumers should branch on `schema_version`.

This phase integrates and serializes data models only. USB, IPC, memory, and
known-vulnerability modules remain declarations and do not perform scans.
Report output must not contain secrets, keys, certificates, personal
identifiers, or exploit payloads. The collector remains read-only and does not
access NAND/eMMC or modify system data.
