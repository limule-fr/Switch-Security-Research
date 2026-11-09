// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/evidence.hpp"

namespace switchscan {

const char* to_string(EvidenceKind kind) noexcept {
    switch (kind) {
    case EvidenceKind::direct_observation: return "DIRECT_OBSERVATION";
    case EvidenceKind::external_validation: return "EXTERNAL_VALIDATION";
    case EvidenceKind::official_reference: return "OFFICIAL_REFERENCE";
    case EvidenceKind::technical_reference: return "TECHNICAL_REFERENCE";
    }
    return "UNKNOWN";
}

} // namespace switchscan
