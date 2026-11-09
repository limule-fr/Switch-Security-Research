// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/check.hpp"

#include <string>
#include <vector>

namespace switchscan {

enum class RuntimeEnvironmentStatus {
    stock_confirmed,
    cfw_detected,
    modified_or_unknown
};

const char* to_string(RuntimeEnvironmentStatus status) noexcept;

enum class DetectionConfidence {
    high,
    limited,
    unknown
};

const char* to_string(DetectionConfidence confidence) noexcept;

struct RuntimeEnvironmentInfo {
    RuntimeEnvironmentStatus status =
        RuntimeEnvironmentStatus::modified_or_unknown;
    DetectionConfidence confidence = DetectionConfidence::unknown;
    std::string source;
    std::string detail;
    std::string limitations;
    std::vector<std::string> evidence_ids;
};

enum class ComponentProvenance {
    nintendo,
    atmosphere,
    homebrew,
    third_party,
    unknown
};

const char* to_string(ComponentProvenance provenance) noexcept;

struct ObservedValue {
    std::string value;
    std::string status = "NOT_ACCESSIBLE";
    std::string detail;
    std::string source;
};

struct ComponentInfo {
    std::string name;
    std::string status;
    std::string detail;
    ComponentProvenance provenance = ComponentProvenance::unknown;
};

struct SystemInfo {
    std::string platform;
    RuntimeEnvironmentInfo runtime_environment;
    ObservedValue firmware;
    ObservedValue installed_image_firmware;
    ObservedValue model;
    std::vector<ComponentInfo> components;
};

class SystemInfoProvider {
public:
    virtual ~SystemInfoProvider() = default;
    virtual SystemInfo collect() = 0;
};

class SystemInfoCheck final : public ScanCheck {
public:
    SystemInfoCheck(SystemInfoProvider& provider, SystemInfo& output);
    const CheckMetadata& metadata() const noexcept override;
    CheckOutcome run() override;

private:
    SystemInfoProvider& provider_;
    SystemInfo& output_;
    CheckMetadata metadata_;
};

} // namespace switchscan
