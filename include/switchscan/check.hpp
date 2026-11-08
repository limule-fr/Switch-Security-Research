#pragma once

#include "switchscan/types.hpp"

#include <string>

namespace switchscan {

struct CheckMetadata {
    std::string id;
    std::string name;
    std::string description;
    Severity severity = Severity::info;
};

struct CheckOutcome {
    ScanStatus status = ScanStatus::inconclusive;
    std::string evidence;
    bool evidence_sufficient = false;
};

// Each check is independent and must perform read-only observations only.
class ScanCheck {
public:
    virtual ~ScanCheck() = default;
    virtual const CheckMetadata& metadata() const noexcept = 0;
    virtual CheckOutcome run() = 0;
};

} // namespace switchscan
