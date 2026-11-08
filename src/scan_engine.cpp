// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/scan_engine.hpp"

#include <algorithm>
#include <exception>
#include <stdexcept>
#include <string>

namespace switchscan {
namespace {

ScanResult make_result(const CheckMetadata& metadata,
                       const CheckOutcome& outcome) {
    ScanResult result;
    result.control_id = metadata.id;
    result.analysis_name = metadata.name;
    result.description = metadata.description;
    result.severity = metadata.severity;
    result.status = outcome.status;
    result.evidence = outcome.evidence;
    result.evidence_sufficient = outcome.evidence_sufficient;
    result.timestamp_utc = current_timestamp_utc();
    return result;
}

} // namespace

ScanEngine::ScanEngine(Logger& logger) : logger_(logger) {}

void ScanEngine::add_check(std::unique_ptr<ScanCheck> check) {
    if (!check) {
        throw std::invalid_argument("A scan check cannot be null");
    }

    const CheckMetadata& metadata = check->metadata();
    if (metadata.id.empty() || metadata.name.empty()) {
        throw std::invalid_argument("A scan check needs a non-empty ID and name");
    }
    const auto duplicate = std::find_if(
        checks_.begin(), checks_.end(), [&metadata](const auto& existing) {
            return existing->metadata().id == metadata.id;
        });
    if (duplicate != checks_.end()) {
        throw std::invalid_argument("Duplicate scan control ID: " + metadata.id);
    }
    checks_.push_back(std::move(check));
}

std::vector<ScanResult> ScanEngine::run_all() {
    std::vector<ScanResult> results;
    results.reserve(checks_.size());

    for (const auto& check : checks_) {
        const CheckMetadata& metadata = check->metadata();
        logger_.log(LogLevel::info, "Starting control " + metadata.id);

        ScanResult result;
        try {
            const CheckOutcome outcome = check->run();
            result = make_result(metadata, outcome);

            if (result.status == ScanStatus::vulnerable &&
                (!result.evidence_sufficient || result.evidence.empty())) {
                logger_.log(
                    LogLevel::warning,
                    "Control " + metadata.id +
                        " reported VULNERABLE without sufficient evidence; "
                        "downgrading to SUSPECT");
                result.status = ScanStatus::suspect;
                result.evidence_sufficient = false;
            }
        } catch (const std::exception& error) {
            logger_.log(LogLevel::error, "Control " + metadata.id +
                                              " failed: " + error.what());
            result = make_result(
                metadata,
                {ScanStatus::inconclusive,
                 std::string("Control execution failed: ") + error.what(),
                 false});
        } catch (...) {
            logger_.log(LogLevel::error,
                        "Control " + metadata.id +
                            " failed with an unknown exception");
            result = make_result(
                metadata,
                {ScanStatus::inconclusive,
                 "Control execution failed with an unknown exception", false});
        }

        results.push_back(std::move(result));
        logger_.log(LogLevel::info, "Finished control " + metadata.id +
                                        " with status " +
                                        to_string(results.back().status));
    }

    return results;
}

} // namespace switchscan
