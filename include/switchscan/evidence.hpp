// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/exploitation_levels.hpp"

#include <string>
#include <vector>

namespace switchscan {

enum class EvidenceKind {
    direct_observation,
    external_validation,
    official_reference,
    technical_reference
};

const char* to_string(EvidenceKind kind) noexcept;

struct EvidenceRecord {
    std::string id;
    std::string control_id;
    EvidenceKind kind = EvidenceKind::direct_observation;
    std::string source;
    std::string method;
    std::string summary;
    std::string collected_at_utc;
    std::string reproducibility;
    std::string limitations;
    std::string target_context;
    std::vector<DemonstratedCapability> demonstrated_capabilities;
};

} // namespace switchscan
