// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/research_module.hpp"

#include <algorithm>
#include <exception>
#include <stdexcept>
#include <utility>

namespace switchscan {
namespace {

bool supports(const std::vector<ScanPlatform>& platforms,
              ScanPlatform platform) {
    return std::find(platforms.begin(), platforms.end(), platform) !=
           platforms.end();
}

class DeclaredResearchModule final : public ResearchModule {
public:
    DeclaredResearchModule(ResearchModuleMetadata metadata,
                           std::vector<ResearchControlMetadata> controls)
        : metadata_(std::move(metadata)), controls_(std::move(controls)) {}

    const ResearchModuleMetadata& metadata() const noexcept override {
        return metadata_;
    }

    const std::vector<ResearchControlMetadata>& controls()
        const noexcept override {
        return controls_;
    }

    CheckOutcome run_control(const ResearchControlMetadata&,
                             ScanPlatform) override {
        throw std::logic_error(
            "Declared research modules do not implement controls");
    }

private:
    ResearchModuleMetadata metadata_;
    std::vector<ResearchControlMetadata> controls_;
};

ResearchControlMetadata declared_control(const std::string& id,
                                         const std::string& name,
                                         const std::string& description,
                                         const std::vector<ScanPlatform>& platforms) {
    return {{id, name, description, Severity::info}, platforms, false};
}

ResearchModuleMetadata module_metadata(
    const std::string& id, const std::string& name,
    const std::vector<ScanPlatform>& platforms) {
    return {id, name, "0.1.0", platforms, {}};
}

ScanResult make_result(const ResearchModuleMetadata& module,
                       const ResearchControlMetadata& control,
                       ScanStatus status, const std::string& evidence) {
    ScanResult result;
    result.module_id = module.id;
    result.control_id = control.check.id;
    result.analysis_name = control.check.name;
    result.description = control.check.description;
    result.severity = control.check.severity;
    result.status = status;
    result.evidence = evidence;
    result.timestamp_utc = current_timestamp_utc();
    return result;
}

void add_module_error(ModuleRunReport& report, Logger& logger,
                     const ResearchModuleMetadata& module,
                     const ResearchControlMetadata& control,
                     const std::string& message) {
    report.errors.push_back({module.id, control.check.id, message});
    logger.log(LogLevel::error, "Module " + module.id + " control " +
                                   control.check.id + " failed: " + message);
}

} // namespace

const char* to_string(ScanPlatform platform) noexcept {
    switch (platform) {
    case ScanPlatform::pc_test: return "PC_TEST";
    case ScanPlatform::horizon: return "HORIZON";
    }
    return "UNKNOWN";
}

void ModuleRegistry::add_module(std::unique_ptr<ResearchModule> module) {
    if (!module) {
        throw std::invalid_argument("A research module cannot be null");
    }

    const ResearchModuleMetadata& metadata = module->metadata();
    if (metadata.id.empty() || metadata.name.empty() ||
        metadata.version.empty() || metadata.platforms.empty()) {
        throw std::invalid_argument(
            "A research module needs an ID, name, version, and platform");
    }
    const auto duplicate_module = std::find_if(
        modules_.begin(), modules_.end(), [&metadata](const auto& existing) {
            return existing->metadata().id == metadata.id;
        });
    if (duplicate_module != modules_.end()) {
        throw std::invalid_argument("Duplicate research module ID: " +
                                    metadata.id);
    }

    std::vector<std::string> registered_control_ids;
    for (const ResearchControlMetadata& control : module->controls()) {
        if (control.check.id.empty() || control.check.name.empty() ||
            control.platforms.empty()) {
            throw std::invalid_argument(
                "A module control needs an ID, name, and platform");
        }
        for (const ScanPlatform platform : control.platforms) {
            if (!supports(metadata.platforms, platform)) {
                throw std::invalid_argument(
                    "Control platform is not supported by its module: " +
                    control.check.id);
            }
        }
        for (const auto& existing_module : modules_) {
            const auto duplicate_control = std::find_if(
                existing_module->controls().begin(),
                existing_module->controls().end(),
                [&control](const ResearchControlMetadata& existing) {
                    return existing.check.id == control.check.id;
                });
            if (duplicate_control != existing_module->controls().end()) {
                throw std::invalid_argument("Duplicate research control ID: " +
                                            control.check.id);
            }
        }
        if (std::find(registered_control_ids.begin(),
                      registered_control_ids.end(),
                      control.check.id) != registered_control_ids.end()) {
            throw std::invalid_argument("Duplicate research control ID: " +
                                        control.check.id);
        }
        registered_control_ids.push_back(control.check.id);
    }

    modules_.push_back(std::move(module));
}

ModuleRunReport ModuleRegistry::run_all(ScanPlatform platform,
                                        Logger& logger) {
    ModuleRunReport report;
    for (const auto& module : modules_) {
        const ResearchModuleMetadata& module_info = module->metadata();
        const bool module_compatible = supports(module_info.platforms, platform);
        report.modules.push_back({module_info, module->controls()});

        for (const ResearchControlMetadata& control : module->controls()) {
            if (!module_compatible ||
                !supports(control.platforms, platform)) {
                report.checks.push_back(make_result(
                    module_info, control, ScanStatus::not_accessible,
                    std::string("Control is not compatible with platform ") +
                        to_string(platform) + "."));
                continue;
            }
            if (!control.implemented) {
                report.checks.push_back(make_result(
                    module_info, control, ScanStatus::inconclusive,
                    "Declared only; this control is not implemented."));
                continue;
            }

            try {
                CheckOutcome outcome = module->run_control(control, platform);
                ScanResult result = make_result(
                    module_info, control, outcome.status, outcome.evidence);
                result.evidence_sufficient = outcome.evidence_sufficient;
                if (result.status == ScanStatus::vulnerable &&
                    (!result.evidence_sufficient || result.evidence.empty())) {
                    result.status = ScanStatus::suspect;
                    result.evidence_sufficient = false;
                    logger.log(
                        LogLevel::warning,
                        "Module control " + control.check.id +
                            " reported VULNERABLE without sufficient evidence; "
                            "downgrading to SUSPECT");
                }
                report.checks.push_back(std::move(result));
            } catch (const std::exception& error) {
                add_module_error(report, logger, module_info, control,
                                 error.what());
            } catch (...) {
                add_module_error(report, logger, module_info, control,
                                 "Unknown exception");
            }
        }
    }
    return report;
}

std::vector<std::unique_ptr<ResearchModule>> make_default_research_modules() {
    const std::vector<ScanPlatform> horizon{ScanPlatform::horizon};
    const std::vector<ScanPlatform> known_vulnerability_platforms{
        ScanPlatform::horizon, ScanPlatform::pc_test};
    std::vector<std::unique_ptr<ResearchModule>> modules;

    modules.emplace_back(new DeclaredResearchModule(
        module_metadata("usb-research", "USB Research", horizon),
        {declared_control("usb.enumeration", "USB enumeration",
                          "Future passive enumeration of devices exposed to the "
                          "authorized Horizon process.",
                          horizon),
         declared_control("usb.descriptors", "USB descriptors",
                          "Future read-only collection of permitted USB "
                          "descriptor metadata.",
                          horizon),
         declared_control("usb.hid", "HID interfaces",
                          "Future inventory of supported HID interfaces; no "
                          "malformed-device testing.",
                          horizon),
         declared_control("usb.drivers", "USB drivers",
                          "Future read-only inventory of driver availability "
                          "and non-sensitive version metadata.",
                          horizon),
         declared_control("usb.driver-errors", "USB driver errors",
                          "Future collection of non-sensitive driver error "
                          "and availability information.",
                          horizon)}));

    modules.emplace_back(new DeclaredResearchModule(
        module_metadata("ipc-research", "IPC Research", horizon),
        {declared_control("ipc.authorized-services", "Authorized services",
                          "Future checks of explicitly authorized Horizon "
                          "services only.",
                          horizon),
         declared_control("ipc.documented-commands", "Documented commands",
                          "Future non-mutating queries for documented service "
                          "commands.",
                          horizon),
         declared_control("ipc.parameter-validation", "Parameter validation",
                          "Future review of documented parameter constraints; "
                          "no fuzzing or malformed IPC.",
                          horizon)}));

    modules.emplace_back(new DeclaredResearchModule(
        module_metadata("memory-research", "Memory Research", horizon),
        {declared_control("memory.limits", "Memory limits",
                          "Future observation of documented process memory "
                          "limits without probing protected regions.",
                          horizon),
         declared_control("memory.object-lifecycle", "Object lifecycle",
                          "Future non-destructive checks of object lifetime "
                          "and resource release.",
                          horizon),
         declared_control("memory.non-destructive", "Non-destructive checks",
                          "Future bounds and consistency checks that do not "
                          "corrupt memory or alter system state.",
                          horizon)}));

    ResearchModuleMetadata known = module_metadata(
        "known-vulnerabilities", "Known Vulnerabilities",
        known_vulnerability_platforms);
    modules.emplace_back(new DeclaredResearchModule(
        std::move(known),
        {declared_control(
            "known-vulnerabilities.version-ranges", "Known version ranges",
            "Future comparison with documented CVE references, affected "
            "versions, and fixed versions. No reference records are bundled.",
            known_vulnerability_platforms)}));

    return modules;
}

} // namespace switchscan
