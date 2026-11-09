// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/inventory.hpp"

#include "switchscan/sha256.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace switchscan {
namespace {

constexpr std::size_t kMaxEntries = 1000;
constexpr std::size_t kMaxManifestEntries = 1000;
constexpr std::uint64_t kMaxManifestBytes = 1024 * 1024;
constexpr unsigned int kMaxDepth = 8;
constexpr std::uint64_t kMaxFileBytes = 64ULL * 1024 * 1024;
constexpr std::size_t kReadBufferBytes = 32 * 1024;
constexpr std::size_t kNroHeaderBytes = 0x80;
constexpr std::size_t kNroMagicOffset = 0x10;

bool valid_digest(const std::string& value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](unsigned char ch) {
               return std::isxdigit(ch) != 0;
           });
}

bool valid_relative_path(const std::string& path) {
    if (path.empty() || path.front() == '/' || path.front() == '\\') {
        return false;
    }
    std::istringstream parts(path);
    std::string part;
    while (std::getline(parts, part, '/')) {
        if (part == ".." || part.empty()) {
            return false;
        }
    }
    return path.find('\\') == std::string::npos;
}

std::string join_path(const std::string& left, const std::string& right) {
    return left.empty() || left.back() == '/' ? left + right
                                                : left + "/" + right;
}

std::string error_text(const char* operation, const std::string& path) {
    std::ostringstream message;
    message << operation << " '" << path << "': " << std::strerror(errno);
    return message.str();
}

std::uint32_t read_u32_le(const std::vector<unsigned char>& bytes,
                          std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

bool has_nro_extension(const std::string& path) {
    if (path.size() < 4) {
        return false;
    }
    const std::size_t offset = path.size() - 4;
    return std::tolower(static_cast<unsigned char>(path[offset])) == '.' &&
           std::tolower(static_cast<unsigned char>(path[offset + 1])) == 'n' &&
           std::tolower(static_cast<unsigned char>(path[offset + 2])) == 'r' &&
           std::tolower(static_cast<unsigned char>(path[offset + 3])) == 'o';
}

void inspect_static_format(const std::vector<unsigned char>& prefix,
                           std::uint64_t actual_size,
                           const std::string& relative_path,
                           ResourceRecord& record) {
    const bool nro_magic =
        prefix.size() >= kNroMagicOffset + 4 &&
        prefix[kNroMagicOffset] == 'N' &&
        prefix[kNroMagicOffset + 1] == 'R' &&
        prefix[kNroMagicOffset + 2] == 'O' &&
        prefix[kNroMagicOffset + 3] == '0';
    if (!nro_magic) {
        if (has_nro_extension(relative_path)) {
            record.format = FileFormat::nro;
            record.static_analysis_status = StaticAnalysisStatus::anomaly;
            record.static_analysis_detail =
                "The .nro extension is present but the NRO0 signature is "
                "missing.";
        } else {
            record.static_analysis_status = StaticAnalysisStatus::inconclusive;
            record.static_analysis_detail =
                "No supported file signature was recognized; no static "
                "format checks were applied.";
        }
        return;
    }

    record.format = FileFormat::nro;
    if (prefix.size() < kNroHeaderBytes) {
        record.static_analysis_status = StaticAnalysisStatus::anomaly;
        record.static_analysis_detail =
            "The NRO signature is present but its fixed header is truncated.";
        return;
    }

    const std::uint64_t declared_size = read_u32_le(prefix, 0x18);
    if (declared_size < kNroHeaderBytes || declared_size > actual_size) {
        record.static_analysis_status = StaticAnalysisStatus::anomaly;
        record.static_analysis_detail =
            "The NRO declared size is outside the actual file bounds.";
        return;
    }

    for (std::size_t segment = 0; segment < 3; ++segment) {
        const std::size_t offset = 0x20 + segment * 8;
        const std::uint64_t file_offset = read_u32_le(prefix, offset);
        const std::uint64_t size = read_u32_le(prefix, offset + 4);
        if (size != 0 &&
            (file_offset < kNroHeaderBytes || file_offset > declared_size ||
             size > declared_size - file_offset)) {
            record.static_analysis_status = StaticAnalysisStatus::anomaly;
            record.static_analysis_detail =
                "An NRO segment range is outside the declared file bounds.";
            return;
        }
    }

    record.static_analysis_status = StaticAnalysisStatus::structurally_valid;
    record.static_analysis_detail =
        "NRO signature, fixed header, declared size, and segment bounds are "
        "structurally consistent; this is not a security verdict.";
}

ResourceRecord analyze_file(const std::string& full_path,
                            const std::string& relative_path,
                            const ReferenceMap& references) {
    ResourceRecord record;
    record.path = relative_path;

    struct stat before {};
    if (lstat(full_path.c_str(), &before) != 0) {
        record.detail = error_text("Cannot inspect", full_path);
        return record;
    }
    if (!S_ISREG(before.st_mode)) {
        record.detail = "Resource is not a regular file";
        record.static_analysis_status = StaticAnalysisStatus::not_accessible;
        record.static_analysis_detail = record.detail;
        return record;
    }
    record.size = before.st_size < 0
                      ? 0
                      : static_cast<std::uint64_t>(before.st_size);
    record.modified_time_utc_seconds =
        static_cast<std::int64_t>(before.st_mtime);
    if (before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) > kMaxFileBytes) {
        record.state = ResourceState::skipped;
        record.detail = "File exceeds the 64 MiB analysis limit";
        return record;
    }

    const int fd = open(full_path.c_str(), O_RDONLY);
    if (fd < 0) {
        record.detail = error_text("Cannot open for reading", full_path);
        record.static_analysis_status = StaticAnalysisStatus::not_accessible;
        record.static_analysis_detail = record.detail;
        return record;
    }

    struct stat opened {};
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino) {
        record.detail = "File identity changed or is not a regular file";
        record.static_analysis_status = StaticAnalysisStatus::inconclusive;
        record.static_analysis_detail = record.detail;
        close(fd);
        return record;
    }

    Sha256 hash;
    unsigned char buffer[kReadBufferBytes];
    std::vector<unsigned char> prefix;
    prefix.reserve(kNroHeaderBytes);
    bool read_ok = true;
    std::uint64_t total_read = 0;
    for (;;) {
        const ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            record.detail = error_text("Cannot read", full_path);
            read_ok = false;
            break;
        }
        const std::size_t prefix_count =
            std::min<std::size_t>(static_cast<std::size_t>(count),
                                  kNroHeaderBytes - prefix.size());
        prefix.insert(prefix.end(), buffer, buffer + prefix_count);
        total_read += static_cast<std::uint64_t>(count);
        if (total_read > kMaxFileBytes) {
            record.state = ResourceState::skipped;
            record.detail = "File grew beyond the 64 MiB analysis limit";
            record.static_analysis_status = StaticAnalysisStatus::not_run;
            record.static_analysis_detail = record.detail;
            close(fd);
            return record;
        }
        hash.update(buffer, static_cast<std::size_t>(count));
    }

    struct stat after {};
    struct stat path_after {};
    const bool stable = fstat(fd, &after) == 0 &&
                        after.st_dev == opened.st_dev &&
                        after.st_ino == opened.st_ino &&
                        after.st_size == opened.st_size &&
                        after.st_mtime == opened.st_mtime &&
                        after.st_ctime == opened.st_ctime &&
                        lstat(full_path.c_str(), &path_after) == 0 &&
                        S_ISREG(path_after.st_mode) &&
                        path_after.st_dev == opened.st_dev &&
                        path_after.st_ino == opened.st_ino;
    close(fd);

    if (!read_ok) {
        record.static_analysis_status = StaticAnalysisStatus::not_accessible;
        record.static_analysis_detail = record.detail;
        return record;
    }
    if (!stable) {
        record.state = ResourceState::inconclusive;
        record.detail = "File changed while it was being analyzed";
        record.static_analysis_status = StaticAnalysisStatus::inconclusive;
        record.static_analysis_detail = record.detail;
        return record;
    }

    record.state = ResourceState::analyzed;
    record.size = static_cast<std::uint64_t>(after.st_size);
    record.modified_time_utc_seconds =
        static_cast<std::int64_t>(after.st_mtime);
    record.sha256 = Sha256::to_hex(hash.finish());
    inspect_static_format(prefix, record.size, relative_path, record);
    const auto reference = references.find(relative_path);
    if (reference == references.end()) {
        record.reference = ReferenceState::unknown;
        record.detail = "No known reference for this path";
    } else if (reference->second == record.sha256) {
        record.reference = ReferenceState::match;
        record.detail = "SHA-256 matches the supplied reference";
    } else {
        record.reference = ReferenceState::mismatch;
        record.detail = "SHA-256 differs from the supplied reference";
    }
    return record;
}

void walk_directory(const std::string& full_path,
                    const std::string& relative_path,
                    unsigned int depth, const ReferenceMap& references,
                    InventoryReport& report) {
    if (report.entry_count >= kMaxEntries) {
        return;
    }
    struct stat expected_dir {};
    if (lstat(full_path.c_str(), &expected_dir) != 0 ||
        !S_ISDIR(expected_dir.st_mode)) {
        report.resources.push_back(
            {relative_path, ResourceState::not_accessible,
             ReferenceState::unknown, 0, {},
             "Directory is unavailable or not an ordinary directory"});
        return;
    }
    DIR* directory = opendir(full_path.c_str());
    if (directory == nullptr) {
        report.resources.push_back(
            {relative_path, ResourceState::not_accessible,
             ReferenceState::unknown, 0, {}, error_text("Cannot open directory",
                                                        full_path)});
        return;
    }

    struct stat current_dir {};
    if (lstat(full_path.c_str(), &current_dir) != 0 ||
        !S_ISDIR(current_dir.st_mode) ||
        expected_dir.st_dev != current_dir.st_dev ||
        expected_dir.st_ino != current_dir.st_ino) {
        report.resources.push_back(
            {relative_path, ResourceState::not_accessible,
             ReferenceState::unknown, 0, {},
             "Directory identity changed or cannot be verified"});
        closedir(directory);
        return;
    }

    errno = 0;
    for (struct dirent* entry = readdir(directory); entry != nullptr;
         entry = readdir(directory)) {
        if (std::string(entry->d_name) == "." ||
            std::string(entry->d_name) == "..") {
            continue;
        }
        if (report.entry_count >= kMaxEntries) {
            break;
        }
        const std::string name(entry->d_name);
        ++report.entry_count;
        const std::string child_path = join_path(full_path, name);
        const std::string child_relative =
            relative_path.empty() ? name : join_path(relative_path, name);
        struct stat info {};
        if (lstat(child_path.c_str(), &info) != 0) {
            report.resources.push_back(
                {child_relative, ResourceState::not_accessible,
                 ReferenceState::unknown, 0, {},
                 error_text("Cannot inspect", child_path)});
        } else if (S_ISLNK(info.st_mode)) {
            report.resources.push_back(
                {child_relative, ResourceState::skipped,
                 ReferenceState::unknown, 0, {}, "Symbolic links are not followed"});
        } else if (S_ISDIR(info.st_mode)) {
            if (depth >= kMaxDepth) {
                report.resources.push_back(
                    {child_relative, ResourceState::skipped,
                     ReferenceState::unknown, 0, {},
                     "Directory exceeds the depth limit"});
            } else {
                walk_directory(child_path, child_relative, depth + 1,
                               references, report);
            }
        } else if (S_ISREG(info.st_mode)) {
            report.resources.push_back(
                analyze_file(child_path, child_relative, references));
        } else {
            report.resources.push_back(
                {child_relative, ResourceState::skipped,
                 ReferenceState::unknown, 0, {},
                 "Resource type is not a regular file or directory"});
        }
        errno = 0;
    }
    if (errno != 0 && report.resources.size() < kMaxEntries) {
        report.resources.push_back(
            {relative_path, ResourceState::not_accessible,
             ReferenceState::unknown, 0, {},
             error_text("Directory traversal failed", full_path)});
    }
    closedir(directory);
}

} // namespace

LoadedReferences load_reference_manifest(const std::string& path) {
    LoadedReferences loaded;
    struct stat manifest_info {};
    if (lstat(path.c_str(), &manifest_info) != 0) {
        loaded.error = "Reference manifest is unavailable: " + path;
        return loaded;
    }
    if (!S_ISREG(manifest_info.st_mode) || manifest_info.st_size < 0 ||
        static_cast<std::uint64_t>(manifest_info.st_size) >
            kMaxManifestBytes) {
        loaded.error =
            "Reference manifest is not a regular file or exceeds the 1 MiB "
            "limit: " +
            path;
        return loaded;
    }
    std::ifstream input(path.c_str());
    if (!input) {
        loaded.error = "Reference manifest is unavailable: " + path;
        return loaded;
    }

    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream row(line);
        std::string digest;
        std::string relative_path;
        if (!(row >> digest >> relative_path) || !valid_digest(digest) ||
            !valid_relative_path(relative_path)) {
            loaded.error = "Invalid reference manifest entry at line " +
                           std::to_string(line_number);
            loaded.hashes.clear();
            return loaded;
        }
        std::transform(digest.begin(), digest.end(), digest.begin(),
                       [](unsigned char ch) {
                           return static_cast<char>(std::tolower(ch));
                       });
        if (!loaded.hashes.emplace(relative_path, digest).second) {
            loaded.error = "Duplicate reference path at line " +
                           std::to_string(line_number);
            loaded.hashes.clear();
            return loaded;
        }
        if (loaded.hashes.size() > kMaxManifestEntries) {
            loaded.error = "Reference manifest exceeds the 1000-entry limit";
            loaded.hashes.clear();
            return loaded;
        }
        std::string extra;
        if (row >> extra) {
            loaded.error = "Unexpected data in reference manifest at line " +
                           std::to_string(line_number);
            loaded.hashes.clear();
            return loaded;
        }
    }
    if (input.bad()) {
        loaded.hashes.clear();
        loaded.error = "Failed while reading reference manifest: " + path;
        return loaded;
    }
    loaded.loaded = true;
    return loaded;
}

FileInventoryCheck::FileInventoryCheck(std::string root, ReferenceMap references,
                                       InventoryReport& output,
                                       bool references_loaded,
                                       std::string reference_error,
                                       std::string reference_source)
    : root_(std::move(root)), references_(std::move(references)), output_(output),
      references_loaded_(references_loaded),
      reference_error_(std::move(reference_error)),
      reference_source_(std::move(reference_source)),
      metadata_{"collector.file-inventory", "Scoped file inventory",
                "Read-only inventory and SHA-256 of regular files under the "
                "configured root only.",
                Severity::medium} {}

const CheckMetadata& FileInventoryCheck::metadata() const noexcept {
    return metadata_;
}

CheckOutcome FileInventoryCheck::run() {
    output_ = InventoryReport{};
    output_.root = root_;
    output_.reference_manifest_loaded = references_loaded_;
    output_.reference_manifest_source = reference_source_;
    output_.reference_manifest_version.clear();
    output_.reference_manifest_error = reference_error_;

    struct stat root_info {};
    if (lstat(root_.c_str(), &root_info) != 0) {
        if (errno == ENOENT) {
            output_.root_status = InventoryRootStatus::absent;
            output_.resources.push_back(
                {".", ResourceState::inconclusive, ReferenceState::unknown,
                 0, {}, "Configured inventory root is absent"});
        } else {
            output_.root_status = InventoryRootStatus::not_accessible;
            output_.resources.push_back(
                {".", ResourceState::not_accessible, ReferenceState::unknown,
                 0, {}, error_text("Cannot inspect inventory root", root_)});
        }
    } else if (!S_ISDIR(root_info.st_mode) || S_ISLNK(root_info.st_mode)) {
        output_.root_status = InventoryRootStatus::not_accessible;
        output_.resources.push_back(
            {".", ResourceState::not_accessible, ReferenceState::unknown, 0, {},
             "Configured inventory root is not an ordinary directory"});
    } else {
        walk_directory(root_, "", 0, references_, output_);
        output_.root_status = output_.entry_count == 0
                                  ? InventoryRootStatus::present_empty
                                  : InventoryRootStatus::present_nonempty;
    }

    for (const ResourceRecord& resource : output_.resources) {
        switch (resource.state) {
        case ResourceState::analyzed:
            ++output_.analyzed_count;
            if (resource.static_analysis_status ==
                StaticAnalysisStatus::anomaly) {
                ++output_.static_anomaly_count;
            }
            if (resource.reference == ReferenceState::mismatch) {
                ++output_.mismatch_count;
            }
            break;
        case ResourceState::not_accessible:
            ++output_.inaccessible_count;
            break;
        case ResourceState::skipped:
            ++output_.skipped_count;
            break;
        case ResourceState::inconclusive:
            ++output_.inconclusive_count;
            break;
        }
    }

    if (output_.inaccessible_count > 0) {
        const bool root_unavailable =
            output_.entry_count == 0 && output_.resources.size() == 1 &&
            (output_.resources.front().path.empty() ||
             output_.resources.front().path == ".");
        output_.root_status =
            root_unavailable ? InventoryRootStatus::not_accessible
                             : InventoryRootStatus::partially_accessible;
    }

    if (output_.entry_count >= kMaxEntries) {
        output_.resources.push_back(
            {"", ResourceState::skipped, ReferenceState::unknown, 0, {},
             "Inventory stopped at the 1000-entry limit"});
        ++output_.skipped_count;
    }

    if (output_.mismatch_count > 0) {
        return {ScanStatus::suspect,
                std::to_string(output_.mismatch_count) +
                    " file hash(es) differ from supplied references; this is "
                    "an integrity discrepancy, not proof of a vulnerability.",
                true};
    }
    if (output_.static_anomaly_count > 0) {
        return {ScanStatus::suspect,
                std::to_string(output_.static_anomaly_count) +
                    " recognized file(s) have structural anomalies; this is "
                    "not evidence of a vulnerability or malicious content.",
                false};
    }
    if (output_.analyzed_count == 0 || output_.inaccessible_count > 0 ||
        output_.skipped_count > 0 || output_.inconclusive_count > 0 ||
        output_.analyzed_count !=
            static_cast<std::size_t>(std::count_if(
                output_.resources.begin(), output_.resources.end(),
                [](const ResourceRecord& resource) {
                    return resource.state == ResourceState::analyzed &&
                           resource.reference == ReferenceState::match;
                }))) {
        return {output_.analyzed_count == 0 &&
                        output_.inaccessible_count > 0
                    ? ScanStatus::not_accessible
                    : ScanStatus::inconclusive,
                "Inventory completed with inaccessible, skipped, or "
                   "unreferenced resources.",
                false};
    }
    return {ScanStatus::ok,
            "All analyzed files matched the supplied reference manifest.", true};
}

const char* to_string(ResourceState state) noexcept {
    switch (state) {
    case ResourceState::analyzed: return "ANALYZED";
    case ResourceState::not_accessible: return "NOT_ACCESSIBLE";
    case ResourceState::skipped: return "SKIPPED";
    case ResourceState::inconclusive: return "INCONCLUSIVE";
    }
    return "NOT_ACCESSIBLE";
}

const char* to_string(InventoryRootStatus status) noexcept {
    switch (status) {
    case InventoryRootStatus::not_accessible: return "NOT_ACCESSIBLE";
    case InventoryRootStatus::absent: return "ABSENT";
    case InventoryRootStatus::present_empty: return "PRESENT_EMPTY";
    case InventoryRootStatus::present_nonempty: return "PRESENT_NONEMPTY";
    case InventoryRootStatus::partially_accessible:
        return "PARTIALLY_ACCESSIBLE";
    }
    return "NOT_ACCESSIBLE";
}

const char* to_string(FileFormat format) noexcept {
    switch (format) {
    case FileFormat::unknown: return "UNKNOWN";
    case FileFormat::nro: return "NRO";
    }
    return "UNKNOWN";
}

const char* to_string(StaticAnalysisStatus status) noexcept {
    switch (status) {
    case StaticAnalysisStatus::not_run: return "NOT_RUN";
    case StaticAnalysisStatus::structurally_valid:
        return "STRUCTURALLY_VALID";
    case StaticAnalysisStatus::anomaly: return "ANOMALY";
    case StaticAnalysisStatus::inconclusive: return "INCONCLUSIVE";
    case StaticAnalysisStatus::not_accessible: return "NOT_ACCESSIBLE";
    }
    return "INCONCLUSIVE";
}

const char* to_string(ReferenceState state) noexcept {
    switch (state) {
    case ReferenceState::match: return "MATCH";
    case ReferenceState::mismatch: return "MISMATCH";
    case ReferenceState::unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

} // namespace switchscan
