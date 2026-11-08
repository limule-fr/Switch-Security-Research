// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/types.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace switchscan {

const char* to_string(Severity severity) noexcept {
    switch (severity) {
    case Severity::info: return "INFO";
    case Severity::low: return "LOW";
    case Severity::medium: return "MEDIUM";
    case Severity::high: return "HIGH";
    case Severity::critical: return "CRITICAL";
    }
    return "INFO";
}

const char* to_string(ScanStatus status) noexcept {
    switch (status) {
    case ScanStatus::ok: return "OK";
    case ScanStatus::suspect: return "SUSPECT";
    case ScanStatus::vulnerable: return "VULNERABLE";
    case ScanStatus::inconclusive: return "INCONCLUSIVE";
    case ScanStatus::not_accessible: return "NOT_ACCESSIBLE";
    }
    return "INCONCLUSIVE";
}

std::string current_timestamp_utc() {
    const std::time_t now = std::time(nullptr);
    const std::tm* utc = std::gmtime(&now);
    if (utc == nullptr) {
        return {};
    }

    std::ostringstream stream;
    stream << std::put_time(utc, "%Y-%m-%dT%H:%M:%SZ");
    return stream ? stream.str() : std::string{};
}

} // namespace switchscan
