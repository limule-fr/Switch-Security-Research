// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/system_info.hpp"

namespace switchscan {

const char* to_string(RuntimeEnvironmentStatus status) noexcept {
    switch (status) {
    case RuntimeEnvironmentStatus::stock_confirmed:
        return "STOCK_CONFIRMED";
    case RuntimeEnvironmentStatus::cfw_detected: return "CFW_DETECTED";
    case RuntimeEnvironmentStatus::modified_or_unknown:
        return "MODIFIED_OR_UNKNOWN";
    }
    return "MODIFIED_OR_UNKNOWN";
}

const char* to_string(DetectionConfidence confidence) noexcept {
    switch (confidence) {
    case DetectionConfidence::high: return "HIGH";
    case DetectionConfidence::limited: return "LIMITED";
    case DetectionConfidence::unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char* to_string(ComponentProvenance provenance) noexcept {
    switch (provenance) {
    case ComponentProvenance::nintendo: return "NINTENDO";
    case ComponentProvenance::atmosphere: return "ATMOSPHERE";
    case ComponentProvenance::homebrew: return "HOMEBREW";
    case ComponentProvenance::third_party: return "THIRD_PARTY";
    case ComponentProvenance::unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

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
