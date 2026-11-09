// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/json_exporter.hpp"
#include "switchscan/inventory.hpp"
#include "switchscan/research_module.hpp"
#include "switchscan/report.hpp"
#include "switchscan/scan_engine.hpp"
#include "switchscan/sha256.hpp"
#include "switchscan/vulnerability.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <unistd.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class FixedCheck final : public switchscan::ScanCheck {
public:
    FixedCheck(std::string id, switchscan::CheckOutcome outcome)
        : metadata_{std::move(id), "Test control", "Test description",
                    switchscan::Severity::high},
          outcome_(std::move(outcome)) {}

    const switchscan::CheckMetadata& metadata() const noexcept override {
        return metadata_;
    }

    switchscan::CheckOutcome run() override {
        return outcome_;
    }

private:
    switchscan::CheckMetadata metadata_;
    switchscan::CheckOutcome outcome_;
};

class ThrowingCheck final : public switchscan::ScanCheck {
public:
    ThrowingCheck()
        : metadata_{"test.throw", "Throwing control", "Failure isolation test",
                    switchscan::Severity::medium} {}

    const switchscan::CheckMetadata& metadata() const noexcept override {
        return metadata_;
    }

    switchscan::CheckOutcome run() override {
        throw std::runtime_error("simulated failure");
    }

private:
    switchscan::CheckMetadata metadata_;
};

class FakeResearchModule final : public switchscan::ResearchModule {
public:
    FakeResearchModule(switchscan::ResearchModuleMetadata metadata,
                       std::vector<switchscan::ResearchControlMetadata> controls,
                       switchscan::CheckOutcome outcome, int& executions,
                       bool throws = false)
        : metadata_(std::move(metadata)), controls_(std::move(controls)),
          outcome_(std::move(outcome)), executions_(executions),
          throws_(throws) {}

    const switchscan::ResearchModuleMetadata& metadata() const noexcept override {
        return metadata_;
    }

    const std::vector<switchscan::ResearchControlMetadata>& controls()
        const noexcept override {
        return controls_;
    }

    switchscan::CheckOutcome run_control(
        const switchscan::ResearchControlMetadata&,
        switchscan::ScanPlatform) override {
        ++executions_;
        if (throws_) {
            throw std::runtime_error("module execution failure");
        }
        return outcome_;
    }

private:
    switchscan::ResearchModuleMetadata metadata_;
    std::vector<switchscan::ResearchControlMetadata> controls_;
    switchscan::CheckOutcome outcome_;
    int& executions_;
    bool throws_;
};

std::unique_ptr<switchscan::ResearchModule> make_fake_module(
    const std::string& module_id, const std::string& control_id,
    switchscan::ScanPlatform platform, switchscan::CheckOutcome outcome,
    int& executions, bool implemented = true, bool throws = false) {
    switchscan::ResearchModuleMetadata metadata{
        module_id, "Test module", "1.0.0", {platform}, {}};
    switchscan::ResearchControlMetadata control{
        {control_id, "Test control", "Test description",
         switchscan::Severity::medium},
        {platform}, implemented};
    return std::unique_ptr<switchscan::ResearchModule>(new FakeResearchModule(
        std::move(metadata), {std::move(control)}, std::move(outcome),
        executions, throws));
}

} // namespace

int main() {
    try {
        require(std::string(switchscan::to_string(
                    switchscan::ExploitationLevel::level0)) == "LEVEL_0" &&
                    std::string(switchscan::to_string(
                    switchscan::ExploitationLevel::level1)) == "LEVEL_1" &&
                    std::string(switchscan::to_string(
                    switchscan::ExploitationLevel::level2)) == "LEVEL_2" &&
                    std::string(switchscan::to_string(
                    switchscan::ExploitationLevel::level3)) == "LEVEL_3" &&
                    std::string(switchscan::to_string(
                    switchscan::ExploitationLevel::level4)) == "LEVEL_4" &&
                    switchscan::is_level_assessable(
                        switchscan::ExploitationLevel::level0) &&
                    switchscan::is_level_assessable(
                        switchscan::ExploitationLevel::level1) &&
                    switchscan::is_level_assessable(
                        switchscan::ExploitationLevel::level2) &&
                    switchscan::is_level_assessable(
                        switchscan::ExploitationLevel::level3) &&
                    !switchscan::is_level_assessable(
                        switchscan::ExploitationLevel::level4),
                "Levels 0-3 must be assessable and level 4 must remain "
                "unassessable until its criteria are defined");

        switchscan::EvidenceRecord direct_evidence{
            "evidence.direct-001", "control.safe-test",
            switchscan::EvidenceKind::direct_observation, "PC_TEST fixture",
            "Deterministic unit-test fixture", "Synthetic direct observation",
            "2026-01-01T00:00:00Z", "Repeatable with the test suite",
            "Synthetic evidence only", "Synthetic PC_TEST fixture", {}};
        switchscan::VulnerabilityFinding confirmed_finding;
        confirmed_finding.id = "finding.synthetic";
        confirmed_finding.title = "Synthetic confirmed finding";
        confirmed_finding.component = "synthetic component";
        confirmed_finding.status = switchscan::VulnerabilityStatus::confirmed;
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.evidence_ids.push_back(direct_evidence.id);
        require(switchscan::validate_finding(confirmed_finding,
                                             {direct_evidence})
                    .empty(),
                "A confirmed level-0 finding with linked direct evidence "
                "must satisfy structural validation");

        switchscan::EvidenceRecord code_execution_evidence = direct_evidence;
        code_execution_evidence.id = "evidence.code-execution";
        code_execution_evidence.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::limited_code_execution};
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level1;
        confirmed_finding.exploitation.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::limited_code_execution};
        confirmed_finding.evidence_ids = {code_execution_evidence.id};
        require(switchscan::validate_finding(confirmed_finding,
                                             {code_execution_evidence})
                    .empty(),
                "A higher achieved level requires matching direct capability "
                "evidence");
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level2;
        require(!switchscan::validate_finding(confirmed_finding,
                                              {code_execution_evidence})
                     .empty(),
                "Code-execution evidence alone must not establish user-homebrew "
                "launch");
        confirmed_finding.exploitation.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::user_homebrew_launch};
        require(!switchscan::validate_finding(confirmed_finding,
                                              {code_execution_evidence})
                     .empty(),
                "A claimed capability must be present in linked direct evidence");
        confirmed_finding.exploitation.demonstrated_capabilities.clear();

        switchscan::EvidenceRecord user_homebrew_evidence =
            code_execution_evidence;
        user_homebrew_evidence.id = "evidence.user-homebrew";
        user_homebrew_evidence.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::user_homebrew_launch};
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level2;
        confirmed_finding.exploitation.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::user_homebrew_launch};
        confirmed_finding.evidence_ids = {user_homebrew_evidence.id};
        require(switchscan::validate_finding(confirmed_finding,
                                             {user_homebrew_evidence})
                    .empty(),
                "Level 2 requires and accepts direct user-homebrew launch evidence");

        switchscan::EvidenceRecord sysmodule_evidence = code_execution_evidence;
        sysmodule_evidence.id = "evidence.homebrew-sysmodule";
        sysmodule_evidence.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::homebrew_sysmodule_load};
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level3;
        confirmed_finding.exploitation.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::homebrew_sysmodule_load};
        confirmed_finding.evidence_ids = {sysmodule_evidence.id};
        require(switchscan::validate_finding(confirmed_finding,
                                             {sysmodule_evidence})
                    .empty(),
                "Level 3 requires and accepts direct sysmodule-load evidence");

        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level1;
        confirmed_finding.exploitation.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::limited_code_execution};
        switchscan::EvidenceRecord missing_context_evidence =
            code_execution_evidence;
        missing_context_evidence.id = "evidence.missing-context";
        missing_context_evidence.target_context.clear();
        confirmed_finding.evidence_ids = {missing_context_evidence.id};
        require(!switchscan::validate_finding(confirmed_finding,
                                              {missing_context_evidence})
                     .empty(),
                "Direct evidence must identify its target context");
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.exploitation.demonstrated_capabilities.clear();
        confirmed_finding.evidence_ids = {direct_evidence.id};

        switchscan::EvidenceRecord advisory_evidence{
            "evidence.advisory-001", "control.version-check",
            switchscan::EvidenceKind::official_reference,
            "Synthetic official advisory", "Reference lookup",
            "Synthetic advisory statement", "2026-01-01T00:00:00Z",
            "Reference can be independently retrieved",
            "Does not prove target applicability", "", {}};
        confirmed_finding.evidence_ids = {advisory_evidence.id};
        const std::vector<switchscan::FindingValidationIssue>
            reference_only_issues =
                switchscan::validate_finding(confirmed_finding,
                                             {advisory_evidence});
        require(!reference_only_issues.empty() &&
                    confirmed_finding.status ==
                        switchscan::VulnerabilityStatus::confirmed,
                "References alone must fail validation without silently "
                "rewriting a finding status");

        confirmed_finding.evidence_ids = {code_execution_evidence.id};
        confirmed_finding.exploitation.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::limited_code_execution};
        confirmed_finding.exploitation.potential_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.exploitation.potential_level_rationale =
            "Synthetic rationale for validation test";
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level1;
        require(!switchscan::validate_finding(confirmed_finding,
                                              {code_execution_evidence})
                     .empty(),
                "Potential level cannot be lower than achieved level");
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.exploitation.demonstrated_capabilities.clear();
        confirmed_finding.evidence_ids = {direct_evidence.id};
        confirmed_finding.exploitation.potential_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.exploitation.potential_level_rationale.clear();
        require(!switchscan::validate_finding(confirmed_finding,
                                              {direct_evidence})
                     .empty(),
                "Potential levels must include their rationale");
        confirmed_finding.exploitation.potential_level_rationale =
            "Synthetic rationale for validation test";
        confirmed_finding.exploitation.chain_level =
            switchscan::ExploitationLevel::level0;
        require(!switchscan::validate_finding(confirmed_finding,
                                              {direct_evidence})
                     .empty(),
                "A chain level must reference a documented chain");
        confirmed_finding.exploitation.chain_level.reset();
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.exploitation.potential_level =
            switchscan::ExploitationLevel::level4;
        require(!switchscan::validate_finding(confirmed_finding,
                                              {direct_evidence})
                     .empty(),
                "Level 4 cannot be assigned as potential without validated criteria");
        confirmed_finding.exploitation.potential_level.reset();
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level4;
        require(!switchscan::validate_finding(confirmed_finding,
                                              {direct_evidence})
                     .empty(),
                "Level 4 cannot be assigned as achieved without validated criteria");
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.exploitation.chain_level =
            switchscan::ExploitationLevel::level4;
        require(!switchscan::validate_finding(confirmed_finding,
                                              {direct_evidence})
                     .empty(),
                "Level 4 cannot be assigned to a chain without validated criteria");
        confirmed_finding.exploitation.chain_level.reset();
        confirmed_finding.evidence_ids = {"evidence.missing"};
        require(!switchscan::validate_finding(confirmed_finding,
                                              {direct_evidence})
                     .empty(),
                "Findings must not reference missing evidence records");

        switchscan::VulnerabilityFinding second_chain_finding =
            confirmed_finding;
        confirmed_finding.evidence_ids = {direct_evidence.id};
        confirmed_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_finding.exploitation.potential_level.reset();
        confirmed_finding.exploitation.potential_level_rationale.clear();
        confirmed_finding.id = "finding.synthetic.first";
        second_chain_finding.id = "finding.synthetic.second";
        second_chain_finding.evidence_ids = {direct_evidence.id};
        second_chain_finding.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        second_chain_finding.exploitation.potential_level.reset();
        second_chain_finding.exploitation.potential_level_rationale.clear();
        switchscan::VulnerabilityChain confirmed_chain;
        confirmed_chain.id = "chain.synthetic";
        confirmed_chain.title = "Synthetic validated chain";
        confirmed_chain.ordered_finding_ids = {
            confirmed_finding.id, second_chain_finding.id};
        confirmed_chain.dependency_rationales = {
            "Synthetic prerequisite relationship"};
        confirmed_chain.status = switchscan::VulnerabilityStatus::confirmed;
        confirmed_chain.exploitation.achieved_level =
            switchscan::ExploitationLevel::level1;
        confirmed_chain.evidence_ids = {code_execution_evidence.id};
        require(switchscan::validate_chain(
                    confirmed_chain,
                    {confirmed_finding, second_chain_finding},
                    {direct_evidence, code_execution_evidence})
                    .empty(),
                "A chain requires ordered confirmed findings, justified "
                "dependencies, and separate direct evidence");

        switchscan::VulnerabilityFinding chained_finding = confirmed_finding;
        chained_finding.exploitation.chain_level =
            switchscan::ExploitationLevel::level1;
        chained_finding.chain_ids = {confirmed_chain.id};
        require(switchscan::validate_finding(
                    chained_finding,
                    {direct_evidence, code_execution_evidence},
                    {confirmed_chain})
                    .empty(),
                "A finding's chain level must link to matching validated chain "
                "evidence");
        confirmed_chain.dependency_rationales.clear();
        require(!switchscan::validate_chain(
                     confirmed_chain,
                     {confirmed_finding, second_chain_finding},
                     {direct_evidence, code_execution_evidence})
                     .empty(),
                "A chain without documented dependency rationale is invalid");

        require(std::string(switchscan::to_string(
                    switchscan::VulnerabilityStatus::confirmed)) ==
                    "CONFIRMED" &&
                    std::string(switchscan::to_string(
                    switchscan::VulnerabilityStatus::suspect)) == "SUSPECT" &&
                    std::string(switchscan::to_string(
                    switchscan::VulnerabilityStatus::inconclusive)) ==
                        "INCONCLUSIVE" &&
                    std::string(switchscan::to_string(
                    switchscan::VulnerabilityStatus::not_accessible)) ==
                        "NOT_ACCESSIBLE" &&
                    std::string(switchscan::to_string(
                    switchscan::EvidenceKind::external_validation)) ==
                    "EXTERNAL_VALIDATION",
                "Finding statuses and evidence provenance must be explicit");
        switchscan::VulnerabilityFinding non_confirmed_finding;
        non_confirmed_finding.id = "finding.non-confirmed";
        non_confirmed_finding.title = "Non-confirmed validation fixture";
        non_confirmed_finding.component = "synthetic component";
        for (const switchscan::VulnerabilityStatus status : {
                 switchscan::VulnerabilityStatus::suspect,
                 switchscan::VulnerabilityStatus::inconclusive,
                 switchscan::VulnerabilityStatus::not_accessible}) {
            non_confirmed_finding.status = status;
            require(switchscan::validate_finding(non_confirmed_finding, {})
                        .empty() &&
                        non_confirmed_finding.status == status,
                    "Non-confirmed statuses must remain distinct and must not "
                    "be rewritten by validation");
        }

        std::ostringstream log_output;
        switchscan::Logger logger(log_output);
        switchscan::ScanEngine engine(logger);
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(new FixedCheck(
            "test.vulnerable-without-proof",
            {switchscan::ScanStatus::vulnerable, "", false})));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new ThrowingCheck()));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(new FixedCheck(
            "test.confirmed-with-proof",
            {switchscan::ScanStatus::vulnerable, "Synthetic test evidence",
             true})));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(new FixedCheck(
            "test.empty-proof",
            {switchscan::ScanStatus::vulnerable, "", true})));

        const std::vector<switchscan::ScanResult> results = engine.run_all();
        require(results.size() == 4, "All independent controls must be run");
        require(results[0].status == switchscan::ScanStatus::suspect,
                "VULNERABLE without proof must be downgraded");
        require(results[1].status == switchscan::ScanStatus::inconclusive,
                "A failed control must be inconclusive");
        require(results[2].status == switchscan::ScanStatus::vulnerable,
                "A finding with explicit sufficient evidence should be retained");
        require(results[3].status == switchscan::ScanStatus::suspect,
                "A finding without evidence must be downgraded");
        require(!results[0].timestamp_utc.empty(),
                "Results must carry a UTC timestamp");
        require(log_output.str().find("simulated failure") != std::string::npos,
                "Control failures must be logged");

        const std::string json = switchscan::JsonExporter::to_json(results);
        require(json.find("\"status\": \"SUSPECT\"") != std::string::npos,
                "JSON must contain the downgraded status");
        require(json.find("\"evidence_sufficient\": true") != std::string::npos,
                "JSON must include evidence sufficiency");
        require(json.find("\"confidence\"") == std::string::npos,
                "JSON must not imply an undefined confidence methodology");

        switchscan::ScanResult escaped;
        escaped.control_id = "test.escape";
        escaped.evidence = "quote: \" slash: \\ newline:\n";
        const std::string escaped_json = switchscan::JsonExporter::to_json({escaped});
        require(escaped_json.find("quote: \\\" slash: \\\\ newline:\\n") !=
                    std::string::npos,
                "JSON strings must escape quotes, backslashes, and newlines");

        bool duplicate_rejected = false;
        switchscan::ScanEngine duplicate_engine(logger);
        duplicate_engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new FixedCheck("duplicate", {})));
        try {
            duplicate_engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
                new FixedCheck("duplicate", {})));
        } catch (const std::invalid_argument&) {
            duplicate_rejected = true;
        }
        require(duplicate_rejected, "Duplicate control IDs must be rejected");

        switchscan::ModuleRegistry default_modules;
        for (auto& module : switchscan::make_default_research_modules()) {
            default_modules.add_module(std::move(module));
        }
        const switchscan::ModuleRunReport horizon_modules =
            default_modules.run_all(switchscan::ScanPlatform::horizon, logger);
        require(horizon_modules.modules.size() == 4 &&
                    horizon_modules.modules[0].metadata.id == "usb-research" &&
                    horizon_modules.modules[1].metadata.id == "ipc-research" &&
                    horizon_modules.modules[2].metadata.id == "memory-research" &&
                    horizon_modules.modules[3].metadata.id ==
                        "known-vulnerabilities",
                "Default modules must be registered with stable identifiers");
        require(horizon_modules.checks.size() == 12 &&
                    horizon_modules.errors.empty(),
                "Declared controls must yield results without runtime errors");
        for (const switchscan::ScanResult& result : horizon_modules.checks) {
            require(result.status == switchscan::ScanStatus::inconclusive &&
                        result.evidence.find("not implemented") !=
                            std::string::npos &&
                        !result.module_id.empty(),
                    "Unimplemented controls must be clearly inconclusive");
        }
        require(horizon_modules.modules[3]
                        .metadata.vulnerability_references.empty(),
                "No CVE references may be implied when no records are loaded");

        const switchscan::ModuleRunReport pc_modules =
            default_modules.run_all(switchscan::ScanPlatform::pc_test, logger);
        require(pc_modules.checks.size() == 12 &&
                    pc_modules.checks[0].status ==
                        switchscan::ScanStatus::not_accessible &&
                    pc_modules.checks.back().status ==
                        switchscan::ScanStatus::inconclusive,
                "Controls incompatible with PC_TEST must not be executed");

        int module_executions = 0;
        switchscan::ModuleRegistry compatible_registry;
        compatible_registry.add_module(make_fake_module(
            "test.module", "test.module.control",
            switchscan::ScanPlatform::horizon,
            {switchscan::ScanStatus::ok, "Synthetic read-only observation",
             false},
            module_executions));
        const switchscan::ModuleRunReport incompatible =
            compatible_registry.run_all(switchscan::ScanPlatform::pc_test,
                                        logger);
        require(module_executions == 0 && incompatible.checks.size() == 1 &&
                    incompatible.checks[0].status ==
                        switchscan::ScanStatus::not_accessible,
                "Platform-incompatible controls must not invoke module code");
        const switchscan::ModuleRunReport compatible =
            compatible_registry.run_all(switchscan::ScanPlatform::horizon,
                                        logger);
        require(module_executions == 1 && compatible.checks.size() == 1 &&
                    compatible.checks[0].status == switchscan::ScanStatus::ok,
                "Compatible implemented controls must return observations");

        switchscan::ModuleRegistry unproven_registry;
        int unproven_executions = 0;
        unproven_registry.add_module(make_fake_module(
            "test.unproven-module", "test.unproven-control",
            switchscan::ScanPlatform::pc_test,
            {switchscan::ScanStatus::vulnerable, "", false},
            unproven_executions));
        const switchscan::ModuleRunReport unproven =
            unproven_registry.run_all(switchscan::ScanPlatform::pc_test,
                                      logger);
        require(unproven.checks.size() == 1 &&
                    unproven.checks[0].status == switchscan::ScanStatus::suspect,
                "VULNERABLE without sufficient evidence must be downgraded");

        switchscan::ModuleRegistry error_registry;
        int failed_executions = 0;
        error_registry.add_module(make_fake_module(
            "test.error-module", "test.error-control",
            switchscan::ScanPlatform::pc_test,
            {switchscan::ScanStatus::ok, "", false}, failed_executions, true,
            true));
        const switchscan::ModuleRunReport failed_module =
            error_registry.run_all(switchscan::ScanPlatform::pc_test, logger);
        require(failed_module.checks.empty() &&
                    failed_module.errors.size() == 1 &&
                    failed_module.errors[0].module_id == "test.error-module" &&
                    failed_module.errors[0].control_id == "test.error-control",
                "Execution errors must be recorded separately from verdicts");

        switchscan::ModuleRegistry duplicate_module_registry;
        int unused_executions = 0;
        duplicate_module_registry.add_module(make_fake_module(
            "test.duplicate-module", "test.first-control",
            switchscan::ScanPlatform::pc_test, {}, unused_executions));
        bool duplicate_module_rejected = false;
        try {
            duplicate_module_registry.add_module(make_fake_module(
                "test.duplicate-module", "test.second-control",
                switchscan::ScanPlatform::pc_test, {}, unused_executions));
        } catch (const std::invalid_argument&) {
            duplicate_module_rejected = true;
        }
        require(duplicate_module_rejected,
                "Duplicate module IDs must be rejected");

        switchscan::ModuleRegistry duplicate_research_control_registry;
        duplicate_research_control_registry.add_module(make_fake_module(
            "test.first-module", "test.shared-control",
            switchscan::ScanPlatform::pc_test, {}, unused_executions));
        bool duplicate_research_control_rejected = false;
        try {
            duplicate_research_control_registry.add_module(make_fake_module(
                "test.second-module", "test.shared-control",
                switchscan::ScanPlatform::pc_test, {}, unused_executions));
        } catch (const std::invalid_argument&) {
            duplicate_research_control_rejected = true;
        }
        require(duplicate_research_control_rejected,
                "Control IDs must be unique across registered modules");

        switchscan::Sha256 sha;
        sha.update("a", 1);
        sha.update("bc", 2);
        require(switchscan::Sha256::to_hex(sha.finish()) ==
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "SHA-256 must match the standard abc test vector");

        char temp_template[] = "build/switchscan-test-XXXXXX";
        char* temp_dir = mkdtemp(temp_template);
        require(temp_dir != nullptr, "A temporary test directory is required");
        const std::string base(temp_dir);
        const std::string input_dir = base + "/input";
        const std::string file_path = input_dir + "/sample.txt";
        const std::string manifest_path = base + "/references.sha256";
        require(mkdir(input_dir.c_str(), 0700) == 0,
                "Test input directory must be created");
        {
            std::ofstream file(file_path.c_str(), std::ios::binary);
            file << "abc";
            require(static_cast<bool>(file), "Test file must be written");
        }
        {
            std::ofstream manifest(manifest_path.c_str());
            manifest << "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        " sample.txt\n";
            require(static_cast<bool>(manifest), "Reference manifest must be written");
        }
        const switchscan::LoadedReferences loaded =
            switchscan::load_reference_manifest(manifest_path);
        require(loaded.loaded && loaded.hashes.size() == 1,
                "Valid SHA-256 reference manifests must load");
        switchscan::InventoryReport inventory;
        switchscan::FileInventoryCheck inventory_check(
            input_dir, loaded.hashes, inventory, loaded.loaded, loaded.error);
        const switchscan::CheckOutcome matched = inventory_check.run();
        require(matched.status == switchscan::ScanStatus::ok &&
                    inventory.analyzed_count == 1 &&
                    inventory.resources[0].reference ==
                        switchscan::ReferenceState::match,
                "Inventory should verify matching references");

        switchscan::FileInventoryCheck mismatch_check(
            input_dir, {{"sample.txt", std::string(64, '0')}}, inventory,
            true, "");
        const switchscan::CheckOutcome mismatch = mismatch_check.run();
        require(mismatch.status == switchscan::ScanStatus::suspect &&
                    inventory.mismatch_count == 1 &&
                    inventory.resources[0].state ==
                        switchscan::ResourceState::analyzed,
                "Reference differences must be reported as suspect integrity "
                "anomalies");

        switchscan::FileInventoryCheck inaccessible_check(
            base + "/missing", {}, inventory, false, "manifest unavailable");
        const switchscan::CheckOutcome inaccessible =
            inaccessible_check.run();
        require(inaccessible.status == switchscan::ScanStatus::not_accessible &&
                    inventory.inaccessible_count == 1,
                "Unavailable roots must not be reported as clean");

        switchscan::ScanReport report;
        report.collector_type = "NRO";
        report.collector_version = "test";
        report.system.platform = "Nintendo Switch / Horizon";
        report.system.firmware = {"23.0.1", "OK", "test fixture", "set:sys"};
        report.system.installed_image_firmware = {
            "", "NOT_ACCESSIBLE", "Not inspected by NRO", "NRO_SCOPE"};
        report.inventory = inventory;
        report.modules = horizon_modules.modules;
        switchscan::ReportExporter::finalize_id(report);
        switchscan::ScanReport second_report = report;
        switchscan::ReportExporter::finalize_id(second_report);
        require(report.report_id.size() == 64 &&
                    second_report.report_id != report.report_id,
                "Report identifiers must be full-length and distinct");
        const std::string report_json =
            switchscan::ReportExporter::to_json(report);
        require(report_json.find("\"schema_version\": 3") != std::string::npos &&
                    report_json.find("\"report_id\": \"" + report.report_id +
                                     "\"") != std::string::npos &&
                    report_json.find("\"collected_at_utc\"") !=
                        std::string::npos &&
                    report_json.find("\"collector_type\": \"NRO\"") !=
                        std::string::npos &&
                    report_json.find("\"collector_version\": \"test\"") !=
                        std::string::npos &&
                    report_json.find("\"research_modules\"") !=
                        std::string::npos &&
                    report_json.find("\"vulnerabilities\"") !=
                        std::string::npos &&
                    report_json.find("\"evidence\"") !=
                        std::string::npos &&
                    report_json.find("\"vulnerability_chains\"") !=
                        std::string::npos &&
                    report_json.find("\"id\": \"usb-research\"") !=
                        std::string::npos &&
                    report_json.find("\"implemented\": false") !=
                        std::string::npos &&
                    report_json.find("\"vulnerability_references\": []") !=
                        std::string::npos &&
                    report_json.find("\"running_os\"") != std::string::npos &&
                    report_json.find("\"installed_image\"") !=
                        std::string::npos &&
                    report_json.find("\"inaccessible_resources\"") !=
                        std::string::npos &&
                    report_json.find("\"errors\"") != std::string::npos,
                "JSON report must include the required schema fields");
        require(report_json.find("\"value\": null") != std::string::npos,
                "Inaccessible firmware values must be null");
        require(report_json.find("\"resource\": \"firmware.installed_image\"") !=
                    std::string::npos,
                "The uncollected installed image must be explicitly inaccessible");
        require(report_json.find("\"confidence\"") == std::string::npos &&
                    report_json.find("\"qr_payload\"") == std::string::npos,
                "Report must not include undefined confidence or QR payload");

        switchscan::ScanReport phase2_report = report;
        const auto make_evidence = [](const std::string& id,
                                      const std::string& summary) {
            return switchscan::EvidenceRecord{
                id,
                "control.synthetic",
                switchscan::EvidenceKind::direct_observation,
                "Synthetic PC_TEST fixture",
                "Deterministic unit-test observation",
                summary,
                "2026-01-01T00:00:00Z",
                "Repeatable with the test suite",
                "Synthetic evidence only",
                "Synthetic PC_TEST context",
                {}};
        };
        phase2_report.evidence = {
            make_evidence("evidence.a1", "First synthetic observation"),
            make_evidence("evidence.a2", "Second synthetic observation"),
            make_evidence("evidence.b1", "Third synthetic observation"),
            make_evidence("evidence.chain", "Synthetic chain validation")};
        phase2_report.evidence.back().demonstrated_capabilities = {
            switchscan::DemonstratedCapability::limited_code_execution};

        switchscan::VulnerabilityFinding confirmed_a;
        confirmed_a.id = "finding.a";
        confirmed_a.title = "Synthetic \"confirmed\"\nfinding";
        confirmed_a.technical_description =
            "Description with quote: \" and newline\npreserved.";
        confirmed_a.component = "synthetic component A";
        confirmed_a.affected_versions = "test-version";
        confirmed_a.status = switchscan::VulnerabilityStatus::confirmed;
        confirmed_a.assessment_status = switchscan::AssessmentStatus::complete;
        confirmed_a.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_a.exploitation.potential_level =
            switchscan::ExploitationLevel::level1;
        confirmed_a.exploitation.potential_level_rationale =
            "A synthetic, explicitly unproven possibility.";
        confirmed_a.evidence_ids = {"evidence.a1", "evidence.a2"};
        confirmed_a.reference_ids = {"reference.synthetic"};
        confirmed_a.chain_ids = {"chain.synthetic"};
        confirmed_a.exploitation.chain_level =
            switchscan::ExploitationLevel::level1;

        switchscan::VulnerabilityFinding confirmed_b;
        confirmed_b.id = "finding.b";
        confirmed_b.title = "Second synthetic confirmed finding";
        confirmed_b.component = "synthetic component B";
        confirmed_b.status = switchscan::VulnerabilityStatus::confirmed;
        confirmed_b.assessment_status = switchscan::AssessmentStatus::complete;
        confirmed_b.exploitation.achieved_level =
            switchscan::ExploitationLevel::level0;
        confirmed_b.evidence_ids = {"evidence.b1"};
        confirmed_b.chain_ids = {"chain.synthetic"};
        confirmed_b.exploitation.chain_level =
            switchscan::ExploitationLevel::level1;

        switchscan::VulnerabilityFinding suspect;
        suspect.id = "finding.suspect";
        suspect.title = "Synthetic suspected finding";
        suspect.component = "synthetic component";
        suspect.status = switchscan::VulnerabilityStatus::suspect;
        suspect.assessment_status = switchscan::AssessmentStatus::inconclusive;
        suspect.assessment_detail = "Evidence is insufficient to confirm.";

        switchscan::VulnerabilityFinding inaccessible_finding;
        inaccessible_finding.id = "finding.inaccessible";
        inaccessible_finding.title = "Unreachable synthetic control";
        inaccessible_finding.component = "synthetic component";
        inaccessible_finding.status =
            switchscan::VulnerabilityStatus::not_accessible;
        inaccessible_finding.assessment_status =
            switchscan::AssessmentStatus::not_accessible;
        inaccessible_finding.limitations =
            "The test resource is unavailable.";

        switchscan::VulnerabilityFinding inconclusive;
        inconclusive.id = "finding.inconclusive";
        inconclusive.title = "Inconclusive synthetic assessment";
        inconclusive.component = "synthetic component";
        inconclusive.status = switchscan::VulnerabilityStatus::inconclusive;
        inconclusive.assessment_status =
            switchscan::AssessmentStatus::partial;
        inconclusive.assessment_detail =
            "The synthetic assessment did not reach a conclusion.";

        switchscan::VulnerabilityChain chain;
        chain.id = "chain.synthetic";
        chain.title = "Synthetic two-finding chain";
        chain.ordered_finding_ids = {"finding.a", "finding.b"};
        chain.dependency_rationales = {
            "The first synthetic finding is a prerequisite for the second."};
        chain.status = switchscan::VulnerabilityStatus::confirmed;
        chain.exploitation.achieved_level =
            switchscan::ExploitationLevel::level1;
        chain.exploitation.demonstrated_capabilities = {
            switchscan::DemonstratedCapability::limited_code_execution};
        chain.evidence_ids = {"evidence.chain"};
        phase2_report.vulnerabilities = {confirmed_a, confirmed_b, suspect,
                                         inaccessible_finding, inconclusive};
        phase2_report.vulnerability_chains = {chain};

        const std::string phase2_json =
            switchscan::ReportExporter::to_json(phase2_report);
        require(phase2_json.find("\"status\": \"SUSPECT\"") !=
                    std::string::npos &&
                    phase2_json.find("\"status\": \"CONFIRMED\"") !=
                        std::string::npos &&
                    phase2_json.find("\"assessment_status\": "
                                     "\"NOT_ACCESSIBLE\"") !=
                        std::string::npos &&
                    phase2_json.find("\"assessment_status\": "
                                     "\"INCONCLUSIVE\"") !=
                        std::string::npos &&
                    phase2_json.find("\"ordered_finding_ids\": "
                                     "[\"finding.a\", \"finding.b\"]") !=
                        std::string::npos &&
                    phase2_json.find("\"evidence_ids\": "
                                     "[\"evidence.a1\", \"evidence.a2\"]") !=
                        std::string::npos &&
                    phase2_json.find("\"reference_ids\": "
                                     "[\"reference.synthetic\"]") !=
                        std::string::npos &&
                    phase2_json.find("\"kind\": "
                                     "\"DIRECT_OBSERVATION\"") !=
                        std::string::npos &&
                    phase2_json.find("\"source\": "
                                     "\"Synthetic PC_TEST fixture\"") !=
                        std::string::npos &&
                    phase2_json.find("\"dependency_rationales\": "
                                     "[\"The first synthetic finding is a "
                                     "prerequisite for the second.\"]") !=
                        std::string::npos &&
                    phase2_json.find("\"achieved_level\": null") !=
                        std::string::npos &&
                    phase2_json.find("\"potential_level\": \"LEVEL_1\"") !=
                        std::string::npos &&
                    phase2_json.find("\"technical_description\": "
                                     "\"Description with quote: \\\" and "
                                     "newline\\npreserved.\"") !=
                        std::string::npos,
                "Schema v3 must preserve findings, evidence links, chains, "
                "null levels, and escaped text");

        const auto rejects_invalid_report = [](switchscan::ScanReport invalid) {
            try {
                (void)switchscan::ReportExporter::to_json(invalid);
            } catch (const std::runtime_error&) {
                return true;
            }
            return false;
        };
        switchscan::ScanReport invalid_chain_report = phase2_report;
        invalid_chain_report.vulnerability_chains[0]
            .dependency_rationales.clear();
        require(rejects_invalid_report(invalid_chain_report),
                "A chain with a missing dependency rationale must be rejected");

        switchscan::ScanReport invalid_level_report = phase2_report;
        invalid_level_report.vulnerabilities[0].exploitation.achieved_level =
            switchscan::ExploitationLevel::level4;
        require(rejects_invalid_report(invalid_level_report),
                "Serialization must reject level 4 as achieved");
        invalid_level_report = phase2_report;
        invalid_level_report.vulnerabilities[0].exploitation.potential_level =
            switchscan::ExploitationLevel::level4;
        require(rejects_invalid_report(invalid_level_report),
                "Serialization must reject level 4 as potential");
        invalid_level_report = phase2_report;
        invalid_level_report.vulnerabilities[0].exploitation.chain_level =
            switchscan::ExploitationLevel::level4;
        require(rejects_invalid_report(invalid_level_report),
                "Serialization must reject level 4 as a finding chain level");
        invalid_level_report = phase2_report;
        invalid_level_report.vulnerability_chains[0]
            .exploitation.achieved_level = switchscan::ExploitationLevel::level4;
        require(rejects_invalid_report(invalid_level_report),
                "Serialization must reject level 4 as a chain achieved level");
        invalid_level_report = phase2_report;
        invalid_level_report.vulnerability_chains[0]
            .exploitation.potential_level = switchscan::ExploitationLevel::level4;
        require(rejects_invalid_report(invalid_level_report),
                "Serialization must reject level 4 as a chain potential level");
        invalid_level_report = phase2_report;
        invalid_level_report.vulnerability_chains[0]
            .exploitation.chain_level = switchscan::ExploitationLevel::level4;
        require(rejects_invalid_report(invalid_level_report),
                "Serialization must reject level 4 as a chain-level field");
        invalid_level_report = phase2_report;
        invalid_level_report.vulnerabilities[0].exploitation.achieved_level =
            static_cast<switchscan::ExploitationLevel>(99);
        require(rejects_invalid_report(invalid_level_report),
                "Unknown exploitation levels must not be serialized");

        const char* fixture_path =
            std::getenv("SWITCHSCAN_REPORT_FIXTURE");
        if (fixture_path != nullptr && fixture_path[0] != '\0') {
            std::ofstream fixture(fixture_path, std::ios::binary);
            require(static_cast<bool>(fixture),
                    "The optional JSON validation fixture must be writable");
            fixture << phase2_json;
            require(static_cast<bool>(fixture),
                    "The optional JSON validation fixture must be complete");
        }

        const std::string reports_dir = base + "/reports";
        require(mkdir(reports_dir.c_str(), 0700) == 0,
                "Test report directory must be created");
        const std::string report_path = reports_dir + "/report.json";
        switchscan::ReportExporter::write_json(report_path, report);
        std::ifstream saved_report(report_path.c_str(), std::ios::binary);
        const std::string saved_contents((std::istreambuf_iterator<char>(
                                              saved_report)),
                                         std::istreambuf_iterator<char>());
        require(saved_contents == report_json,
                "The saved report must match the standalone JSON output");

        bool existing_report_rejected = false;
        try {
            switchscan::ReportExporter::write_json(report_path, report);
        } catch (const std::runtime_error&) {
            existing_report_rejected = true;
        }
        require(existing_report_rejected,
                "An existing report must never be overwritten");
        require(access((report_path + ".tmp-" + report.report_id).c_str(),
                       F_OK) != 0,
                "Temporary report must be cleaned after a name collision");
        std::ifstream unchanged_report(report_path.c_str(), std::ios::binary);
        const std::string unchanged_contents((std::istreambuf_iterator<char>(
                                                  unchanged_report)),
                                             std::istreambuf_iterator<char>());
        require(unchanged_contents == saved_contents,
                "A failed duplicate write must preserve the existing report");

        bool write_error_reported = false;
        try {
            switchscan::ReportExporter::write_json(
                base + "/missing/output.json", report);
        } catch (const std::runtime_error&) {
            write_error_reported = true;
        }
        require(write_error_reported,
                "An unavailable output directory must report a write failure");
        require(access((base + "/missing/output.json.tmp-" + report.report_id)
                           .c_str(),
                       F_OK) != 0,
                "Temporary report must be cleaned after an output error");

        unlink(file_path.c_str());
        unlink(manifest_path.c_str());
        unlink(report_path.c_str());
        rmdir(reports_dir.c_str());
        rmdir(input_dir.c_str());
        rmdir(base.c_str());

        std::cout << "All scanner core tests passed.\n";
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
