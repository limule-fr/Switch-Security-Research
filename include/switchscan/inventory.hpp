// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "switchscan/check.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
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

struct ResourceRecord {
    std::string path;
    ResourceState state = ResourceState::not_accessible;
    ReferenceState reference = ReferenceState::unknown;
    std::uint64_t size = 0;
    std::string sha256;
    std::string detail;
};

struct InventoryReport {
    std::string root;
    std::vector<ResourceRecord> resources;
    std::size_t analyzed_count = 0;
    std::size_t inaccessible_count = 0;
    std::size_t skipped_count = 0;
    std::size_t inconclusive_count = 0;
    std::size_t mismatch_count = 0;
    bool reference_manifest_loaded = false;
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
                       std::string reference_error);
    const CheckMetadata& metadata() const noexcept override;
    CheckOutcome run() override;

private:
    std::string root_;
    ReferenceMap references_;
    InventoryReport& output_;
    bool references_loaded_;
    std::string reference_error_;
    CheckMetadata metadata_;
};

const char* to_string(ResourceState state) noexcept;
const char* to_string(ReferenceState state) noexcept;

} // namespace switchscan
