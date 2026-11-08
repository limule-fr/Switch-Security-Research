#pragma once

#include "switchscan/check.hpp"

#include <string>
#include <vector>

namespace switchscan {

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
};

struct SystemInfo {
    std::string platform;
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
