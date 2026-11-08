// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/inventory.hpp"
#include "switchscan/research_module.hpp"
#include "switchscan/system_info.hpp"
#include "switchscan/types.hpp"

#include <string>
#include <vector>

namespace switchscan {

struct ReportError {
    std::string source;
    std::string message;
};

struct ScanReport {
    std::string report_id;
    std::string collected_at_utc;
    std::string collector_type = "NRO";
    std::string collector_version = "development";
    SystemInfo system;
    InventoryReport inventory;
    std::vector<ResearchModuleRecord> modules;
    std::vector<ScanResult> checks;
    std::vector<ReportError> errors;
};

class ReportExporter {
public:
    static void finalize_id(ScanReport& report);
    static std::string to_json(const ScanReport& report);
    static void write_json(const std::string& json_path,
                           const ScanReport& report);
};

} // namespace switchscan
