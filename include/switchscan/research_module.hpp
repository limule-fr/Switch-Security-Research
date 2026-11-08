// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/check.hpp"
#include "switchscan/logger.hpp"

#include <memory>
#include <string>
#include <vector>

namespace switchscan {

enum class ScanPlatform {
    pc_test,
    horizon
};

const char* to_string(ScanPlatform platform) noexcept;

struct VulnerabilityReference {
    std::string id;
    std::string source;
    std::string affected_versions;
    std::string fixed_versions;
};

struct ResearchControlMetadata {
    CheckMetadata check;
    std::vector<ScanPlatform> platforms;
    bool implemented = false;
};

struct ResearchModuleMetadata {
    std::string id;
    std::string name;
    std::string version;
    std::vector<ScanPlatform> platforms;
    std::vector<VulnerabilityReference> vulnerability_references;
};

struct ResearchModuleRecord {
    ResearchModuleMetadata metadata;
    std::vector<ResearchControlMetadata> controls;
};

struct ModuleExecutionError {
    std::string module_id;
    std::string control_id;
    std::string message;
};

struct ModuleRunReport {
    std::vector<ResearchModuleRecord> modules;
    std::vector<ScanResult> checks;
    std::vector<ModuleExecutionError> errors;
};

class ResearchModule {
public:
    virtual ~ResearchModule() = default;
    virtual const ResearchModuleMetadata& metadata() const noexcept = 0;
    virtual const std::vector<ResearchControlMetadata>& controls()
        const noexcept = 0;
    virtual CheckOutcome run_control(const ResearchControlMetadata& control,
                                     ScanPlatform platform) = 0;
};

class ModuleRegistry {
public:
    void add_module(std::unique_ptr<ResearchModule> module);
    ModuleRunReport run_all(ScanPlatform platform, Logger& logger);

private:
    std::vector<std::unique_ptr<ResearchModule>> modules_;
};

std::vector<std::unique_ptr<ResearchModule>> make_default_research_modules();

} // namespace switchscan
