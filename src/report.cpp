// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/report.hpp"

#include "switchscan/sha256.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace switchscan {
namespace {

void write_string(std::ostream& output, const std::string& value) {
    output << '"';
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (ch < 0x20) {
                output << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << static_cast<int>(ch) << std::dec
                       << std::setfill(' ');
            } else {
                output << static_cast<char>(ch);
            }
        }
    }
    output << '"';
}

void write_nullable_string(std::ostream& output, const std::string& value) {
    if (value.empty()) {
        output << "null";
    } else {
        write_string(output, value);
    }
}

void write_runtime_environment(std::ostream& output,
                               const RuntimeEnvironmentInfo& environment) {
    output << "{\"status\": ";
    write_string(output, to_string(environment.status));
    output << ", \"confidence\": ";
    write_string(output, to_string(environment.confidence));
    output << ", \"source\": ";
    write_nullable_string(output, environment.source);
    output << ", \"detail\": ";
    write_string(output, environment.detail);
    output << ", \"limitations\": ";
    write_string(output, environment.limitations);
    output << ", \"evidence_ids\": [";
    for (std::size_t i = 0; i < environment.evidence_ids.size(); ++i) {
        output << (i == 0 ? "" : ", ");
        write_string(output, environment.evidence_ids[i]);
    }
    output << ']';
    output << '}';
}

void write_observed_value(std::ostream& output, const ObservedValue& value) {
    output << "{\"status\": ";
    write_string(output, value.status);
    output << ", \"value\": ";
    if (value.status == "OK") {
        write_nullable_string(output, value.value);
    } else {
        output << "null";
    }
    output << ", \"source\": ";
    write_nullable_string(output, value.source);
    output << ", \"detail\": ";
    write_string(output, value.detail);
    output << '}';
}

void write_check(std::ostream& output, const ScanResult& check) {
    output << "{\n      \"module_id\": ";
    write_nullable_string(output, check.module_id);
    output << ",\n      \"control_id\": ";
    write_string(output, check.control_id);
    output << ",\n      \"analysis_name\": ";
    write_string(output, check.analysis_name);
    output << ",\n      \"description\": ";
    write_string(output, check.description);
    output << ",\n      \"severity\": ";
    write_string(output, to_string(check.severity));
    output << ",\n      \"status\": ";
    write_string(output, to_string(check.status));
    output << ",\n      \"evidence\": ";
    write_string(output, check.evidence);
    output << ",\n      \"evidence_sufficient\": "
           << (check.evidence_sufficient ? "true" : "false")
           << ",\n      \"timestamp_utc\": ";
    write_nullable_string(output, check.timestamp_utc);
    output << "\n    }";
}

void write_platforms(std::ostream& output,
                     const std::vector<ScanPlatform>& platforms) {
    output << '[';
    for (std::size_t i = 0; i < platforms.size(); ++i) {
        output << (i == 0 ? "" : ", ");
        write_string(output, to_string(platforms[i]));
    }
    output << ']';
}

void write_module(std::ostream& output, const ResearchModuleRecord& module) {
    output << "{\n      \"id\": ";
    write_string(output, module.metadata.id);
    output << ",\n      \"name\": ";
    write_string(output, module.metadata.name);
    output << ",\n      \"version\": ";
    write_string(output, module.metadata.version);
    output << ",\n      \"platforms\": ";
    write_platforms(output, module.metadata.platforms);
    output << ",\n      \"controls\": [";
    for (std::size_t i = 0; i < module.controls.size(); ++i) {
        const ResearchControlMetadata& control = module.controls[i];
        output << (i == 0 ? "\n        {" : ",\n        {")
               << "\"id\": ";
        write_string(output, control.check.id);
        output << ", \"name\": ";
        write_string(output, control.check.name);
        output << ", \"description\": ";
        write_string(output, control.check.description);
        output << ", \"severity\": ";
        write_string(output, to_string(control.check.severity));
        output << ", \"platforms\": ";
        write_platforms(output, control.platforms);
        output << ", \"implemented\": "
               << (control.implemented ? "true" : "false") << '}';
    }
    if (!module.controls.empty()) {
        output << '\n' << "      ";
    }
    output << "],\n      \"vulnerability_references\": [";
    for (std::size_t i = 0;
         i < module.metadata.vulnerability_references.size(); ++i) {
        const VulnerabilityReference& reference =
            module.metadata.vulnerability_references[i];
        output << (i == 0 ? "\n        {" : ",\n        {")
               << "\"id\": ";
        write_string(output, reference.id);
        output << ", \"source\": ";
        write_string(output, reference.source);
        output << ", \"affected_versions\": ";
        write_string(output, reference.affected_versions);
        output << ", \"fixed_versions\": ";
        write_string(output, reference.fixed_versions);
        output << '}';
    }
    if (!module.metadata.vulnerability_references.empty()) {
        output << '\n' << "      ";
    }
    output << "]\n    }";
}

void write_string_array(std::ostream& output,
                        const std::vector<std::string>& values) {
    output << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        output << (i == 0 ? "" : ", ");
        write_string(output, values[i]);
    }
    output << ']';
}

void write_capabilities(std::ostream& output,
                        const std::vector<DemonstratedCapability>& values) {
    output << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        output << (i == 0 ? "" : ", ");
        write_string(output, to_string(values[i]));
    }
    output << ']';
}

void write_level(std::ostream& output,
                 const std::optional<ExploitationLevel>& level) {
    if (level) {
        write_string(output, to_string(*level));
    } else {
        output << "null";
    }
}

void write_level4_context(std::ostream& output,
                          const std::optional<Level4Assessment>& context) {
    if (!context) {
        output << "null";
        return;
    }
    output << "{\"initial_environment\": ";
    write_string(output, to_string(context->initial_environment));
    output << ", \"console_model\": ";
    write_string(output, context->console_model);
    output << ", \"hardware_revision\": ";
    write_string(output, context->hardware_revision);
    output << ", \"firmware_version\": ";
    write_string(output, context->firmware_version);
    output << ", \"execution_mode\": ";
    write_string(output, to_string(context->execution_mode));
    output << ", \"prerequisites\": ";
    write_string(output, context->prerequisites);
    output << ", \"reproduction_procedure\": ";
    write_nullable_string(output, context->reproduction_procedure);
    output << ", \"independent_validation\": ";
    write_string(output, to_string(context->independent_validation));
    output << ", \"independent_validation_detail\": ";
    write_nullable_string(output, context->independent_validation_detail);
    output << ", \"initial_environment_evidence_ids\": ";
    write_string_array(output, context->initial_environment_evidence_ids);
    output << '}';
}

void write_exploitation(std::ostream& output,
                        const ExploitationAssessment& assessment) {
    output << "{\"achieved_level\": ";
    write_level(output, assessment.achieved_level);
    output << ", \"potential_level\": ";
    write_level(output, assessment.potential_level);
    output << ", \"chain_level\": ";
    write_level(output, assessment.chain_level);
    output << ", \"demonstrated_capabilities\": ";
    write_capabilities(output, assessment.demonstrated_capabilities);
    output << ", \"unproven_capabilities\": ";
    write_string_array(output, assessment.unproven_capabilities);
    output << ", \"potential_level_rationale\": ";
    write_nullable_string(output, assessment.potential_level_rationale);
    output << ", \"level4_context\": ";
    write_level4_context(output, assessment.level4);
    output << '}';
}

void write_finding(std::ostream& output, const VulnerabilityFinding& finding) {
    output << "{\n      \"id\": ";
    write_string(output, finding.id);
    output << ",\n      \"title\": ";
    write_string(output, finding.title);
    output << ",\n      \"technical_description\": ";
    write_string(output, finding.technical_description);
    output << ",\n      \"status\": ";
    write_string(output, to_string(finding.status));
    output << ",\n      \"assessment_status\": ";
    write_string(output, to_string(finding.assessment_status));
    output << ",\n      \"assessment_detail\": ";
    write_nullable_string(output, finding.assessment_detail);
    output << ",\n      \"component\": ";
    write_string(output, finding.component);
    output << ",\n      \"affected_versions\": ";
    write_nullable_string(output, finding.affected_versions);
    output << ",\n      \"exploitation\": ";
    write_exploitation(output, finding.exploitation);
    output << ",\n      \"evidence_ids\": ";
    write_string_array(output, finding.evidence_ids);
    output << ",\n      \"reference_ids\": ";
    write_string_array(output, finding.reference_ids);
    output << ",\n      \"chain_ids\": ";
    write_string_array(output, finding.chain_ids);
    output << ",\n      \"reproducibility\": ";
    write_nullable_string(output, finding.reproducibility);
    output << ",\n      \"limitations\": ";
    write_nullable_string(output, finding.limitations);
    output << "\n    }";
}

void write_evidence(std::ostream& output, const EvidenceRecord& evidence) {
    output << "{\n      \"id\": ";
    write_string(output, evidence.id);
    output << ",\n      \"control_id\": ";
    write_string(output, evidence.control_id);
    output << ",\n      \"kind\": ";
    write_string(output, to_string(evidence.kind));
    output << ",\n      \"source\": ";
    write_string(output, evidence.source);
    output << ",\n      \"method\": ";
    write_string(output, evidence.method);
    output << ",\n      \"summary\": ";
    write_string(output, evidence.summary);
    output << ",\n      \"collected_at_utc\": ";
    write_nullable_string(output, evidence.collected_at_utc);
    output << ",\n      \"reproducibility\": ";
    write_nullable_string(output, evidence.reproducibility);
    output << ",\n      \"target_context\": ";
    write_nullable_string(output, evidence.target_context);
    output << ",\n      \"limitations\": ";
    write_nullable_string(output, evidence.limitations);
    output << ",\n      \"demonstrated_capabilities\": ";
    write_capabilities(output, evidence.demonstrated_capabilities);
    output << "\n    }";
}

void write_chain(std::ostream& output, const VulnerabilityChain& chain) {
    output << "{\n      \"id\": ";
    write_string(output, chain.id);
    output << ",\n      \"title\": ";
    write_string(output, chain.title);
    output << ",\n      \"status\": ";
    write_string(output, to_string(chain.status));
    output << ",\n      \"ordered_finding_ids\": ";
    write_string_array(output, chain.ordered_finding_ids);
    output << ",\n      \"dependency_rationales\": ";
    write_string_array(output, chain.dependency_rationales);
    output << ",\n      \"exploitation\": ";
    write_exploitation(output, chain.exploitation);
    output << ",\n      \"evidence_ids\": ";
    write_string_array(output, chain.evidence_ids);
    output << ",\n      \"limitations\": ";
    write_nullable_string(output, chain.limitations);
    output << "\n    }";
}

bool valid_vulnerability_status(VulnerabilityStatus status) {
    switch (status) {
    case VulnerabilityStatus::confirmed:
    case VulnerabilityStatus::suspect:
    case VulnerabilityStatus::inconclusive:
    case VulnerabilityStatus::not_accessible:
        return true;
    }
    return false;
}

bool valid_assessment_status(AssessmentStatus status) {
    switch (status) {
    case AssessmentStatus::complete:
    case AssessmentStatus::partial:
    case AssessmentStatus::inconclusive:
    case AssessmentStatus::not_accessible:
        return true;
    }
    return false;
}

bool valid_environment_status(RuntimeEnvironmentStatus status) {
    switch (status) {
    case RuntimeEnvironmentStatus::stock_confirmed:
    case RuntimeEnvironmentStatus::cfw_detected:
    case RuntimeEnvironmentStatus::modified_or_unknown:
        return true;
    }
    return false;
}

bool valid_detection_confidence(DetectionConfidence confidence) {
    switch (confidence) {
    case DetectionConfidence::high:
    case DetectionConfidence::limited:
    case DetectionConfidence::unknown:
        return true;
    }
    return false;
}

void validate_report_data(const ScanReport& report) {
    std::set<std::string> evidence_ids;
    for (const EvidenceRecord& evidence : report.evidence) {
        if (evidence.id.empty() || !evidence_ids.insert(evidence.id).second) {
            throw std::runtime_error(
                "Report evidence IDs must be non-empty and unique.");
        }
        if (evidence.control_id.empty() || evidence.source.empty() ||
            evidence.method.empty() || evidence.summary.empty() ||
            std::string(to_string(evidence.kind)) == "UNKNOWN") {
            throw std::runtime_error(
                "Report evidence must include valid provenance and content.");
        }
        if ((evidence.kind == EvidenceKind::direct_observation ||
             evidence.kind == EvidenceKind::external_validation) &&
            (evidence.reproducibility.empty() ||
             evidence.target_context.empty())) {
            throw std::runtime_error(
                "Direct evidence requires reproducibility and target context.");
        }
        for (const DemonstratedCapability capability :
             evidence.demonstrated_capabilities) {
            if (std::string(to_string(capability)) == "UNKNOWN") {
                throw std::runtime_error(
                    "Evidence contains an unknown demonstrated capability.");
            }
        }
    }

    const RuntimeEnvironmentInfo& environment =
        report.system.runtime_environment;
    if (!valid_environment_status(environment.status) ||
        !valid_detection_confidence(environment.confidence)) {
        throw std::runtime_error(
            "Report runtime environment contains an unknown status or "
            "confidence.");
    }
    if (environment.status == RuntimeEnvironmentStatus::stock_confirmed) {
        if (environment.confidence != DetectionConfidence::high ||
            environment.source.empty() || environment.detail.empty() ||
            environment.evidence_ids.empty()) {
            throw std::runtime_error(
                "Stock environment confirmation requires high confidence, "
                "provenance, detail, and linked evidence.");
        }
        std::set<std::string> seen_environment_evidence;
        for (const std::string& id : environment.evidence_ids) {
            if (id.empty() || !seen_environment_evidence.insert(id).second) {
                throw std::runtime_error(
                    "Stock environment evidence IDs must be non-empty and "
                    "unique.");
            }
            const auto record = std::find_if(
                report.evidence.begin(), report.evidence.end(),
                [&id](const EvidenceRecord& item) { return item.id == id; });
            if (record == report.evidence.end() ||
                (record->kind != EvidenceKind::direct_observation &&
                 record->kind != EvidenceKind::external_validation)) {
                throw std::runtime_error(
                    "Stock environment confirmation references missing or "
                    "non-direct evidence.");
            }
        }
    } else if (environment.status == RuntimeEnvironmentStatus::cfw_detected) {
        if (environment.confidence != DetectionConfidence::high ||
            environment.source.empty() || environment.detail.empty()) {
            throw std::runtime_error(
                "A detected CFW environment requires a direct source and "
                "high-confidence detail.");
        }
    } else if (environment.confidence == DetectionConfidence::high) {
        throw std::runtime_error(
            "An unknown or modified environment cannot have high confidence.");
    }

    std::set<std::string> finding_ids;
    for (const VulnerabilityFinding& finding : report.vulnerabilities) {
        if (finding.id.empty() || !finding_ids.insert(finding.id).second) {
            throw std::runtime_error(
                "Report vulnerability IDs must be non-empty and unique.");
        }
        if (!valid_vulnerability_status(finding.status) ||
            !valid_assessment_status(finding.assessment_status)) {
            throw std::runtime_error(
                "Report vulnerability contains an unknown status.");
        }
    }

    std::set<std::string> chain_ids;
    for (const VulnerabilityChain& chain : report.vulnerability_chains) {
        if (chain.id.empty() || !chain_ids.insert(chain.id).second) {
            throw std::runtime_error(
                "Report vulnerability-chain IDs must be non-empty and unique.");
        }
        if (!valid_vulnerability_status(chain.status)) {
            throw std::runtime_error(
                "Report vulnerability chain contains an unknown status.");
        }
    }

    for (const VulnerabilityChain& chain : report.vulnerability_chains) {
        const std::vector<FindingValidationIssue> issues =
            validate_chain(chain, report.vulnerabilities, report.evidence);
        if (!issues.empty()) {
            throw std::runtime_error("Invalid vulnerability chain '" +
                                     chain.id + "': " + issues.front().message);
        }
    }
    for (const VulnerabilityFinding& finding : report.vulnerabilities) {
        const std::vector<FindingValidationIssue> issues =
            validate_finding(finding, report.evidence,
                             report.vulnerability_chains);
        if (!issues.empty()) {
            throw std::runtime_error("Invalid vulnerability '" + finding.id +
                                     "': " + issues.front().message);
        }
    }
}

std::string error_message(const char* operation, const std::string& path,
                          int error) {
    return std::string(operation) + " '" + path + "': " +
           std::strerror(error);
}

bool unlink_path(const std::string& path) {
    return unlink(path.c_str()) == 0 || errno == ENOENT;
}

void write_all(int fd, const std::string& path, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t count =
            write(fd, data.data() + offset, data.size() - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(
                error_message("Cannot write temporary JSON report", path,
                              errno));
        }
        if (count == 0) {
            throw std::runtime_error(
                "Short write while writing temporary JSON report: " + path);
        }
        offset += static_cast<std::size_t>(count);
    }
}

void cleanup_temp(const std::string& path, const std::string& cause) {
    if (!unlink_path(path)) {
        throw std::runtime_error(
            cause + "; additionally cannot remove temporary report '" + path +
            "': " + std::strerror(errno));
    }
}

void write_inaccessible_resource(std::ostream& output, bool& first,
                                 const std::string& resource,
                                 const std::string& source,
                                 const std::string& detail) {
    output << (first ? "\n    " : ",\n    ") << "{\"resource\": ";
    write_string(output, resource);
    output << ", \"status\": \"NOT_ACCESSIBLE\", \"source\": ";
    write_nullable_string(output, source);
    output << ", \"detail\": ";
    write_string(output, detail);
    output << '}';
    first = false;
}

} // namespace

void ReportExporter::finalize_id(ScanReport& report) {
    static std::atomic<std::uint64_t> sequence{0};
    report.collected_at_utc = current_timestamp_utc();

    std::ostringstream seed;
    seed << report.collected_at_utc << report.collector_type
         << report.collector_version
         << std::chrono::steady_clock::now().time_since_epoch().count()
         << sequence.fetch_add(1, std::memory_order_relaxed);
    Sha256 hash;
    const std::string seed_text = seed.str();
    hash.update(seed_text.data(), seed_text.size());
    report.report_id = Sha256::to_hex(hash.finish());
    if (report.collected_at_utc.empty()) {
        report.errors.push_back(
            {"clock", "UTC collection time is unavailable."});
    }
}

std::string ReportExporter::to_json(const ScanReport& report) {
    validate_report_data(report);
    std::ostringstream output;
    output << "{\n  \"schema_version\": 3,\n  \"report_id\": ";
    write_nullable_string(output, report.report_id);
    output << ",\n  \"collected_at_utc\": ";
    write_nullable_string(output, report.collected_at_utc);
    output << ",\n  \"collector_type\": ";
    write_string(output, report.collector_type);
    output << ",\n  \"collector_version\": ";
    write_string(output, report.collector_version);
    output << ",\n  \"runtime_environment\": ";
    write_runtime_environment(output, report.system.runtime_environment);
    output << ",\n  \"firmware\": {\n    \"running_os\": ";
    write_observed_value(output, report.system.firmware);
    output << ",\n    \"installed_image\": ";
    write_observed_value(output, report.system.installed_image_firmware);
    output << "\n  },\n  \"system\": {\n    \"platform\": ";
    write_string(output, report.system.platform);
    output << ",\n    \"model\": ";
    write_observed_value(output, report.system.model);
    output << ",\n    \"components\": [";
    for (std::size_t i = 0; i < report.system.components.size(); ++i) {
        const ComponentInfo& component = report.system.components[i];
        output << (i == 0 ? "\n      " : ",\n      ") << "{\"name\": ";
        write_string(output, component.name);
        output << ", \"status\": ";
        write_string(output, component.status);
        output << ", \"source\": ";
        write_string(output, component.name);
        output << ", \"provenance\": ";
        write_string(output, to_string(component.provenance));
        output << ", \"detail\": ";
        write_string(output, component.detail);
        output << '}';
    }
    if (!report.system.components.empty()) {
        output << '\n';
    }
    output << "    ]\n  },\n  \"inventory\": {\n    \"root\": ";
    write_string(output, report.inventory.root);
    output << ",\n    \"root_status\": ";
    write_string(output, to_string(report.inventory.root_status));
    output << ",\n    \"entry_count\": " << report.inventory.entry_count
           << ",\n    \"reference_manifest_loaded\": "
           << (report.inventory.reference_manifest_loaded ? "true" : "false")
           << ",\n    \"reference_manifest_source\": ";
    write_nullable_string(output, report.inventory.reference_manifest_source);
    output << ",\n    \"reference_manifest_version\": ";
    write_nullable_string(output, report.inventory.reference_manifest_version);
    output << ",\n    \"reference_manifest_error\": ";
    write_nullable_string(output, report.inventory.reference_manifest_error);
    output << ",\n    \"counts\": {\"analyzed\": "
           << report.inventory.analyzed_count << ", \"not_accessible\": "
           << report.inventory.inaccessible_count << ", \"skipped\": "
           << report.inventory.skipped_count << ", \"hash_mismatch\": "
           << report.inventory.mismatch_count << ", \"inconclusive\": "
           << report.inventory.inconclusive_count
           << ", \"static_anomalies\": "
           << report.inventory.static_anomaly_count
           << "},\n    \"resources\": [";
    for (std::size_t i = 0; i < report.inventory.resources.size(); ++i) {
        const ResourceRecord& resource = report.inventory.resources[i];
        output << (i == 0 ? "\n      " : ",\n      ") << "{\"path\": ";
        write_string(output, resource.path);
        output << ", \"state\": ";
        write_string(output, to_string(resource.state));
        output << ", \"reference\": ";
        write_string(output, to_string(resource.reference));
        output << ", \"size\": " << resource.size << ", \"sha256\": ";
        write_nullable_string(output, resource.sha256);
        output << ", \"modified_time_utc_seconds\": ";
        if (resource.modified_time_utc_seconds) {
            output << *resource.modified_time_utc_seconds;
        } else {
            output << "null";
        }
        output << ", \"format\": ";
        write_string(output, to_string(resource.format));
        output << ", \"static_analysis_status\": ";
        write_string(output, to_string(resource.static_analysis_status));
        output << ", \"static_analysis_detail\": ";
        write_nullable_string(output, resource.static_analysis_detail);
        output << ", \"detail\": ";
        write_string(output, resource.detail);
        output << '}';
    }
    if (!report.inventory.resources.empty()) {
        output << '\n';
    }
    output << "    ]\n  },\n  \"research_modules\": [";
    for (std::size_t i = 0; i < report.modules.size(); ++i) {
        output << (i == 0 ? "\n    " : ",\n    ");
        write_module(output, report.modules[i]);
    }
    if (!report.modules.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"vulnerabilities\": [";
    for (std::size_t i = 0; i < report.vulnerabilities.size(); ++i) {
        output << (i == 0 ? "\n    " : ",\n    ");
        write_finding(output, report.vulnerabilities[i]);
    }
    if (!report.vulnerabilities.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"evidence\": [";
    for (std::size_t i = 0; i < report.evidence.size(); ++i) {
        output << (i == 0 ? "\n    " : ",\n    ");
        write_evidence(output, report.evidence[i]);
    }
    if (!report.evidence.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"vulnerability_chains\": [";
    for (std::size_t i = 0; i < report.vulnerability_chains.size(); ++i) {
        output << (i == 0 ? "\n    " : ",\n    ");
        write_chain(output, report.vulnerability_chains[i]);
    }
    if (!report.vulnerability_chains.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"checks\": [";
    for (std::size_t i = 0; i < report.checks.size(); ++i) {
        output << (i == 0 ? "\n    " : ",\n    ");
        write_check(output, report.checks[i]);
    }
    if (!report.checks.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"inaccessible_resources\": [";
    bool first_inaccessible = true;
    if (report.system.firmware.status == "NOT_ACCESSIBLE") {
        write_inaccessible_resource(
            output, first_inaccessible, "firmware.running_os",
            report.system.firmware.source, report.system.firmware.detail);
    }
    if (report.system.installed_image_firmware.status == "NOT_ACCESSIBLE") {
        write_inaccessible_resource(output, first_inaccessible,
                                    "firmware.installed_image",
                                    report.system.installed_image_firmware.source,
                                    report.system.installed_image_firmware.detail);
    }
    if (report.system.model.status == "NOT_ACCESSIBLE") {
        write_inaccessible_resource(output, first_inaccessible, "system.model",
                                    report.system.model.source,
                                    report.system.model.detail);
    }
    for (const ComponentInfo& component : report.system.components) {
        if (component.status == "NOT_ACCESSIBLE") {
            write_inaccessible_resource(output, first_inaccessible,
                                        component.name, component.name,
                                        component.detail);
        }
    }
    for (const ResourceRecord& resource : report.inventory.resources) {
        if (resource.state == ResourceState::not_accessible) {
            write_inaccessible_resource(output, first_inaccessible,
                                        resource.path, report.inventory.root,
                                        resource.detail);
        }
    }
    for (const ScanResult& check : report.checks) {
        if (check.status == ScanStatus::not_accessible) {
            write_inaccessible_resource(output, first_inaccessible,
                                        check.control_id, check.control_id,
                                        check.evidence);
        }
    }
    if (!first_inaccessible) {
        output << '\n';
    }
    output << "  ],\n  \"errors\": [";
    for (std::size_t i = 0; i < report.errors.size(); ++i) {
        const ReportError& error = report.errors[i];
        output << (i == 0 ? "\n    " : ",\n    ") << "{\"source\": ";
        write_string(output, error.source);
        output << ", \"message\": ";
        write_string(output, error.message);
        output << '}';
    }
    if (!report.errors.empty()) {
        output << '\n';
    }
    output << "  ]\n}\n";
    return output.str();
}

void ReportExporter::write_json(const std::string& json_path,
                                const ScanReport& report) {
    const std::string temporary_path = json_path + ".tmp-" + report.report_id;
    const std::string json = to_json(report);

    int temporary_fd =
        open(temporary_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (temporary_fd < 0) {
        throw std::runtime_error(
            error_message("Cannot create temporary JSON report",
                          temporary_path, errno));
    }

    try {
        write_all(temporary_fd, temporary_path, json);
        if (fsync(temporary_fd) != 0) {
            const int error = errno;
            throw std::runtime_error(error_message(
                "Cannot flush temporary JSON report", temporary_path, error));
        }
        if (close(temporary_fd) != 0) {
            temporary_fd = -1;
            const int error = errno;
            throw std::runtime_error(error_message(
                "Cannot close temporary JSON report", temporary_path, error));
        }
        temporary_fd = -1;
    } catch (const std::exception& error) {
        std::string failure = error.what();
        if (temporary_fd >= 0) {
            if (close(temporary_fd) != 0) {
                failure += "; additionally cannot close temporary report: ";
                failure += std::strerror(errno);
            }
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }

#ifdef SWITCHSCAN_HORIZON
    // Keep the destination absent; fsdev maps rename to the SD filesystem API.
    struct stat current_info {};
    if (lstat(json_path.c_str(), &current_info) == 0) {
        const std::string failure =
            "JSON report already exists; refusing to overwrite: " + json_path;
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (errno != ENOENT) {
        const std::string failure =
            error_message("Cannot check JSON report path", json_path, errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (rename(temporary_path.c_str(), json_path.c_str()) != 0) {
        const std::string failure =
            error_message("Cannot finalize JSON report", json_path, errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
#else
    const int reservation_fd =
        open(json_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (reservation_fd < 0) {
        const std::string failure =
            error_message("Cannot reserve JSON report path", json_path, errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }

    struct stat reserved_info {};
    if (fstat(reservation_fd, &reserved_info) != 0) {
        const int error = errno;
        std::string failure =
            error_message("Cannot verify reserved JSON report", json_path,
                          error);
        if (close(reservation_fd) != 0) {
            failure += "; additionally cannot close reserved report: ";
            failure += std::strerror(errno);
        }
        if (!unlink_path(json_path)) {
            failure += "; additionally cannot remove reserved path: ";
            failure += std::strerror(errno);
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (close(reservation_fd) != 0) {
        const int error = errno;
        std::string failure =
            error_message("Cannot close reserved JSON report", json_path,
                          error);
        if (!unlink_path(json_path)) {
            failure += "; additionally cannot remove reserved path: ";
            failure += std::strerror(errno);
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }

    struct stat current_info {};
    if (lstat(json_path.c_str(), &current_info) != 0) {
        const std::string failure =
            error_message("Cannot verify reserved JSON report", json_path,
                          errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (current_info.st_dev != reserved_info.st_dev ||
        current_info.st_ino != reserved_info.st_ino) {
        const std::string failure =
            "Reserved JSON report path changed before finalization: " +
            json_path;
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (rename(temporary_path.c_str(), json_path.c_str()) != 0) {
        const int error = errno;
        const bool same_reservation =
            lstat(json_path.c_str(), &current_info) == 0 &&
            current_info.st_dev == reserved_info.st_dev &&
            current_info.st_ino == reserved_info.st_ino;
        std::string failure =
            error_message("Cannot finalize JSON report", json_path, error);
        if (same_reservation && !unlink_path(json_path)) {
            failure += "; cannot remove reserved report path: ";
            failure += std::strerror(errno);
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
#endif
}

} // namespace switchscan
