#include "switchscan/report.hpp"

#include "switchscan/sha256.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace switchscan {
namespace {

void write_string(std::ostream& output, const std::string& value) {
    output << '"';
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (ch < 0x20) {
                output << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << static_cast<int>(ch) << std::dec
                       << std::setfill(' ');
            } else {
                output << static_cast<char>(ch);
            }
        }
    }
    output << '"';
}

void write_nullable_string(std::ostream& output, const std::string& value) {
    if (value.empty()) {
        output << "null";
    } else {
        write_string(output, value);
    }
}

void write_observed_value(std::ostream& output, const ObservedValue& value) {
    output << "{\"status\": ";
    write_string(output, value.status);
    output << ", \"value\": ";
    if (value.status == "OK") {
        write_nullable_string(output, value.value);
    } else {
        output << "null";
    }
    output << ", \"source\": ";
    write_nullable_string(output, value.source);
    output << ", \"detail\": ";
    write_string(output, value.detail);
    output << '}';
}

void write_check(std::ostream& output, const ScanResult& check) {
    output << "{\n      \"control_id\": ";
    write_string(output, check.control_id);
    output << ",\n      \"analysis_name\": ";
    write_string(output, check.analysis_name);
    output << ",\n      \"description\": ";
    write_string(output, check.description);
    output << ",\n      \"severity\": ";
    write_string(output, to_string(check.severity));
    output << ",\n      \"status\": ";
    write_string(output, to_string(check.status));
    output << ",\n      \"evidence\": ";
    write_string(output, check.evidence);
    output << ",\n      \"evidence_sufficient\": "
           << (check.evidence_sufficient ? "true" : "false")
           << ",\n      \"timestamp_utc\": ";
    write_nullable_string(output, check.timestamp_utc);
    output << "\n    }";
}

std::string error_message(const char* operation, const std::string& path,
                          int error) {
    return std::string(operation) + " '" + path + "': " +
           std::strerror(error);
}

bool unlink_path(const std::string& path) {
    return unlink(path.c_str()) == 0 || errno == ENOENT;
}

void write_all(int fd, const std::string& path, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t count =
            write(fd, data.data() + offset, data.size() - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(
                error_message("Cannot write temporary JSON report", path,
                              errno));
        }
        if (count == 0) {
            throw std::runtime_error(
                "Short write while writing temporary JSON report: " + path);
        }
        offset += static_cast<std::size_t>(count);
    }
}

void cleanup_temp(const std::string& path, const std::string& cause) {
    if (!unlink_path(path)) {
        throw std::runtime_error(
            cause + "; additionally cannot remove temporary report '" + path +
            "': " + std::strerror(errno));
    }
}

void write_inaccessible_resource(std::ostream& output, bool& first,
                                 const std::string& resource,
                                 const std::string& source,
                                 const std::string& detail) {
    output << (first ? "\n    " : ",\n    ") << "{\"resource\": ";
    write_string(output, resource);
    output << ", \"status\": \"NOT_ACCESSIBLE\", \"source\": ";
    write_nullable_string(output, source);
    output << ", \"detail\": ";
    write_string(output, detail);
    output << '}';
    first = false;
}

} // namespace

void ReportExporter::finalize_id(ScanReport& report) {
    static std::atomic<std::uint64_t> sequence{0};
    report.collected_at_utc = current_timestamp_utc();

    std::ostringstream seed;
    seed << report.collected_at_utc << report.collector_type
         << report.collector_version
         << std::chrono::steady_clock::now().time_since_epoch().count()
         << sequence.fetch_add(1, std::memory_order_relaxed);
    Sha256 hash;
    const std::string seed_text = seed.str();
    hash.update(seed_text.data(), seed_text.size());
    report.report_id = Sha256::to_hex(hash.finish());
    if (report.collected_at_utc.empty()) {
        report.errors.push_back(
            {"clock", "UTC collection time is unavailable."});
    }
}

std::string ReportExporter::to_json(const ScanReport& report) {
    std::ostringstream output;
    output << "{\n  \"schema_version\": 1,\n  \"report_id\": ";
    write_nullable_string(output, report.report_id);
    output << ",\n  \"collected_at_utc\": ";
    write_nullable_string(output, report.collected_at_utc);
    output << ",\n  \"collector_type\": ";
    write_string(output, report.collector_type);
    output << ",\n  \"collector_version\": ";
    write_string(output, report.collector_version);
    output << ",\n  \"firmware\": {\n    \"running_os\": ";
    write_observed_value(output, report.system.firmware);
    output << ",\n    \"installed_image\": ";
    write_observed_value(output, report.system.installed_image_firmware);
    output << "\n  },\n  \"system\": {\n    \"platform\": ";
    write_string(output, report.system.platform);
    output << ",\n    \"model\": ";
    write_observed_value(output, report.system.model);
    output << ",\n    \"components\": [";
    for (std::size_t i = 0; i < report.system.components.size(); ++i) {
        const ComponentInfo& component = report.system.components[i];
        output << (i == 0 ? "\n      " : ",\n      ") << "{\"name\": ";
        write_string(output, component.name);
        output << ", \"status\": ";
        write_string(output, component.status);
        output << ", \"source\": ";
        write_string(output, component.name);
        output << ", \"detail\": ";
        write_string(output, component.detail);
        output << '}';
    }
    if (!report.system.components.empty()) {
        output << '\n';
    }
    output << "    ]\n  },\n  \"inventory\": {\n    \"root\": ";
    write_string(output, report.inventory.root);
    output << ",\n    \"reference_manifest_loaded\": "
           << (report.inventory.reference_manifest_loaded ? "true" : "false")
           << ",\n    \"reference_manifest_error\": ";
    write_nullable_string(output, report.inventory.reference_manifest_error);
    output << ",\n    \"counts\": {\"analyzed\": "
           << report.inventory.analyzed_count << ", \"not_accessible\": "
           << report.inventory.inaccessible_count << ", \"skipped\": "
           << report.inventory.skipped_count << ", \"hash_mismatch\": "
           << report.inventory.mismatch_count << ", \"inconclusive\": "
           << report.inventory.inconclusive_count
           << "},\n    \"resources\": [";
    for (std::size_t i = 0; i < report.inventory.resources.size(); ++i) {
        const ResourceRecord& resource = report.inventory.resources[i];
        output << (i == 0 ? "\n      " : ",\n      ") << "{\"path\": ";
        write_string(output, resource.path);
        output << ", \"state\": ";
        write_string(output, to_string(resource.state));
        output << ", \"reference\": ";
        write_string(output, to_string(resource.reference));
        output << ", \"size\": " << resource.size << ", \"sha256\": ";
        write_nullable_string(output, resource.sha256);
        output << ", \"detail\": ";
        write_string(output, resource.detail);
        output << '}';
    }
    if (!report.inventory.resources.empty()) {
        output << '\n';
    }
    output << "    ]\n  },\n  \"checks\": [";
    for (std::size_t i = 0; i < report.checks.size(); ++i) {
        output << (i == 0 ? "\n    " : ",\n    ");
        write_check(output, report.checks[i]);
    }
    if (!report.checks.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"inaccessible_resources\": [";
    bool first_inaccessible = true;
    if (report.system.firmware.status == "NOT_ACCESSIBLE") {
        write_inaccessible_resource(
            output, first_inaccessible, "firmware.running_os",
            report.system.firmware.source, report.system.firmware.detail);
    }
    if (report.system.installed_image_firmware.status == "NOT_ACCESSIBLE") {
        write_inaccessible_resource(output, first_inaccessible,
                                    "firmware.installed_image",
                                    report.system.installed_image_firmware.source,
                                    report.system.installed_image_firmware.detail);
    }
    if (report.system.model.status == "NOT_ACCESSIBLE") {
        write_inaccessible_resource(output, first_inaccessible, "system.model",
                                    report.system.model.source,
                                    report.system.model.detail);
    }
    for (const ComponentInfo& component : report.system.components) {
        if (component.status == "NOT_ACCESSIBLE") {
            write_inaccessible_resource(output, first_inaccessible,
                                        component.name, component.name,
                                        component.detail);
        }
    }
    for (const ResourceRecord& resource : report.inventory.resources) {
        if (resource.state == ResourceState::not_accessible) {
            write_inaccessible_resource(output, first_inaccessible,
                                        resource.path, report.inventory.root,
                                        resource.detail);
        }
    }
    for (const ScanResult& check : report.checks) {
        if (check.status == ScanStatus::not_accessible) {
            write_inaccessible_resource(output, first_inaccessible,
                                        check.control_id, check.control_id,
                                        check.evidence);
        }
    }
    if (!first_inaccessible) {
        output << '\n';
    }
    output << "  ],\n  \"errors\": [";
    for (std::size_t i = 0; i < report.errors.size(); ++i) {
        const ReportError& error = report.errors[i];
        output << (i == 0 ? "\n    " : ",\n    ") << "{\"source\": ";
        write_string(output, error.source);
        output << ", \"message\": ";
        write_string(output, error.message);
        output << '}';
    }
    if (!report.errors.empty()) {
        output << '\n';
    }
    output << "  ]\n}\n";
    return output.str();
}

void ReportExporter::write_json(const std::string& json_path,
                                const ScanReport& report) {
    const std::string temporary_path = json_path + ".tmp-" + report.report_id;
    const std::string json = to_json(report);

    int temporary_fd =
        open(temporary_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (temporary_fd < 0) {
        throw std::runtime_error(
            error_message("Cannot create temporary JSON report",
                          temporary_path, errno));
    }

    try {
        write_all(temporary_fd, temporary_path, json);
        if (fsync(temporary_fd) != 0) {
            const int error = errno;
            throw std::runtime_error(error_message(
                "Cannot flush temporary JSON report", temporary_path, error));
        }
        if (close(temporary_fd) != 0) {
            temporary_fd = -1;
            const int error = errno;
            throw std::runtime_error(error_message(
                "Cannot close temporary JSON report", temporary_path, error));
        }
        temporary_fd = -1;
    } catch (const std::exception& error) {
        std::string failure = error.what();
        if (temporary_fd >= 0) {
            if (close(temporary_fd) != 0) {
                failure += "; additionally cannot close temporary report: ";
                failure += std::strerror(errno);
            }
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }

#ifdef SWITCHSCAN_HORIZON
    // Keep the destination absent; fsdev maps rename to the SD filesystem API.
    struct stat current_info {};
    if (lstat(json_path.c_str(), &current_info) == 0) {
        const std::string failure =
            "JSON report already exists; refusing to overwrite: " + json_path;
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (errno != ENOENT) {
        const std::string failure =
            error_message("Cannot check JSON report path", json_path, errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (rename(temporary_path.c_str(), json_path.c_str()) != 0) {
        const std::string failure =
            error_message("Cannot finalize JSON report", json_path, errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
#else
    const int reservation_fd =
        open(json_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (reservation_fd < 0) {
        const std::string failure =
            error_message("Cannot reserve JSON report path", json_path, errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }

    struct stat reserved_info {};
    if (fstat(reservation_fd, &reserved_info) != 0) {
        const int error = errno;
        std::string failure =
            error_message("Cannot verify reserved JSON report", json_path,
                          error);
        if (close(reservation_fd) != 0) {
            failure += "; additionally cannot close reserved report: ";
            failure += std::strerror(errno);
        }
        if (!unlink_path(json_path)) {
            failure += "; additionally cannot remove reserved path: ";
            failure += std::strerror(errno);
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (close(reservation_fd) != 0) {
        const int error = errno;
        std::string failure =
            error_message("Cannot close reserved JSON report", json_path,
                          error);
        if (!unlink_path(json_path)) {
            failure += "; additionally cannot remove reserved path: ";
            failure += std::strerror(errno);
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }

    struct stat current_info {};
    if (lstat(json_path.c_str(), &current_info) != 0) {
        const std::string failure =
            error_message("Cannot verify reserved JSON report", json_path,
                          errno);
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (current_info.st_dev != reserved_info.st_dev ||
        current_info.st_ino != reserved_info.st_ino) {
        const std::string failure =
            "Reserved JSON report path changed before finalization: " +
            json_path;
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
    if (rename(temporary_path.c_str(), json_path.c_str()) != 0) {
        const int error = errno;
        const bool same_reservation =
            lstat(json_path.c_str(), &current_info) == 0 &&
            current_info.st_dev == reserved_info.st_dev &&
            current_info.st_ino == reserved_info.st_ino;
        std::string failure =
            error_message("Cannot finalize JSON report", json_path, error);
        if (same_reservation && !unlink_path(json_path)) {
            failure += "; cannot remove reserved report path: ";
            failure += std::strerror(errno);
        }
        cleanup_temp(temporary_path, failure);
        throw std::runtime_error(failure);
    }
#endif
}

} // namespace switchscan
