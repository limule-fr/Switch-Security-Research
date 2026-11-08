// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/types.hpp"

#include <string>
#include <vector>

namespace switchscan {

class JsonExporter {
public:
    static std::string to_json(const std::vector<ScanResult>& results);
    static void write_file(const std::string& path,
                           const std::vector<ScanResult>& results);
};

} // namespace switchscan
