// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/check.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace switchscan {

enum class ResourceState {
    analyzed,
    not_accessible,
    skipped,
    inconclusive
};

enum class ReferenceState {
    match,
    mismatch,
    unknown
};

enum class InventoryRootStatus {
    not_accessible,
    absent,
    present_empty,
    present_nonempty,
    partially_accessible
};

const char* to_string(InventoryRootStatus status) noexcept;

enum class FileFormat {
    unknown,
    nro
};

const char* to_string(FileFormat format) noexcept;

enum class StaticAnalysisStatus {
    not_run,
    structurally_valid,
    anomaly,
    inconclusive,
    not_accessible
};

const char* to_string(StaticAnalysisStatus status) noexcept;

struct ResourceRecord {
    ResourceRecord() = default;
    ResourceRecord(std::string path_value, ResourceState state_value,
                   ReferenceState reference_value, std::uint64_t size_value,
                   std::string sha256_value, std::string detail_value)
        : path(std::move(path_value)), state(state_value),
          reference(reference_value), size(size_value),
          sha256(std::move(sha256_value)), detail(std::move(detail_value)) {}

    std::string path;
    ResourceState state = ResourceState::not_accessible;
    ReferenceState reference = ReferenceState::unknown;
    std::uint64_t size = 0;
    std::string sha256;
    std::string detail;
    std::optional<std::int64_t> modified_time_utc_seconds;
    FileFormat format = FileFormat::unknown;
    StaticAnalysisStatus static_analysis_status = StaticAnalysisStatus::not_run;
    std::string static_analysis_detail;
};

struct InventoryReport {
    std::string root;
    InventoryRootStatus root_status = InventoryRootStatus::not_accessible;
    std::size_t entry_count = 0;
    std::vector<ResourceRecord> resources;
    std::size_t analyzed_count = 0;
    std::size_t inaccessible_count = 0;
    std::size_t skipped_count = 0;
    std::size_t inconclusive_count = 0;
    std::size_t mismatch_count = 0;
    std::size_t static_anomaly_count = 0;
    bool reference_manifest_loaded = false;
    std::string reference_manifest_source;
    std::string reference_manifest_version;
    std::string reference_manifest_error;
};

using ReferenceMap = std::map<std::string, std::string>;

struct LoadedReferences {
    ReferenceMap hashes;
    bool loaded = false;
    std::string error;
};

LoadedReferences load_reference_manifest(const std::string& path);

class FileInventoryCheck final : public ScanCheck {
public:
    FileInventoryCheck(std::string root, ReferenceMap references,
                       InventoryReport& output, bool references_loaded,
                       std::string reference_error,
                       std::string reference_source = {});
    const CheckMetadata& metadata() const noexcept override;
    CheckOutcome run() override;

private:
    std::string root_;
    ReferenceMap references_;
    InventoryReport& output_;
    bool references_loaded_;
    std::string reference_error_;
    std::string reference_source_;
    CheckMetadata metadata_;
};

const char* to_string(ResourceState state) noexcept;
const char* to_string(ReferenceState state) noexcept;

} // namespace switchscan
