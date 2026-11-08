#pragma once

#include <string>

namespace switchscan {

enum class Severity {
    info,
    low,
    medium,
    high,
    critical
};

enum class ScanStatus {
    ok,
    suspect,
    vulnerable,
    inconclusive,
    not_accessible
};

struct ScanResult {
    std::string control_id;
    std::string analysis_name;
    std::string description;
    Severity severity = Severity::info;
    ScanStatus status = ScanStatus::inconclusive;
    std::string evidence;
    bool evidence_sufficient = false;
    std::string timestamp_utc;
};

const char* to_string(Severity severity) noexcept;
const char* to_string(ScanStatus status) noexcept;
std::string current_timestamp_utc();

} // namespace switchscan
