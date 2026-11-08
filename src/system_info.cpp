#include "switchscan/system_info.hpp"

namespace switchscan {

SystemInfoCheck::SystemInfoCheck(SystemInfoProvider& provider, SystemInfo& output)
    : provider_(provider), output_(output),
      metadata_{"collector.system-info", "System information",
                "Collects only system attributes exposed to this homebrew.",
                Severity::info} {}

const CheckMetadata& SystemInfoCheck::metadata() const noexcept {
    return metadata_;
}

CheckOutcome SystemInfoCheck::run() {
    output_ = provider_.collect();
    const bool firmware_available = output_.firmware.status == "OK";
    const bool model_available = output_.model.status == "OK";
    if (firmware_available && model_available) {
        return {ScanStatus::ok,
                "Firmware and product model were returned by the platform "
                "provider.",
                true};
    }
    if (!firmware_available && !model_available) {
        return {ScanStatus::not_accessible,
                "System information services were unavailable or denied.",
                false};
    }
    return {ScanStatus::inconclusive,
            "Only part of the requested system information was accessible.",
            false};
}

} // namespace switchscan
