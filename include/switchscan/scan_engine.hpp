// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/check.hpp"
#include "switchscan/logger.hpp"
#include "switchscan/types.hpp"

#include <memory>
#include <vector>

namespace switchscan {

class ScanEngine {
public:
    explicit ScanEngine(Logger& logger);

    // Ownership is transferred to the engine. Control IDs must be unique.
    void add_check(std::unique_ptr<ScanCheck> check);
    std::vector<ScanResult> run_all();

private:
    Logger& logger_;
    std::vector<std::unique_ptr<ScanCheck>> checks_;
};

} // namespace switchscan
