#include "switchscan/inventory.hpp"
#include "switchscan/platform.hpp"
#include "switchscan/report.hpp"
#include "switchscan/scan_engine.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <sys/stat.h>

#ifdef SWITCHSCAN_HORIZON
#include <switch.h>
#endif

#ifndef SWITCHSCAN_VERSION
#define SWITCHSCAN_VERSION "development"
#endif

namespace {

struct Options {
    std::string root = "scan-input";
    std::string references = "scan-references.sha256";
    std::string output = "build/scan-report.json";
};

#ifndef SWITCHSCAN_HORIZON
bool parse_options(int argc, char* argv[], Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument(argv[i]);
        if (argument == "--help") {
            std::cout << "Usage: " << argv[0]
                      << " [--root DIR] [--references FILE] [--output FILE]\n";
            return false;
        }
        if ((argument == "--root" || argument == "--references" ||
             argument == "--output") &&
            i + 1 < argc) {
            const std::string value(argv[++i]);
            if (value.empty()) {
                std::cerr << "Option value cannot be empty: " << argument
                          << '\n';
                return false;
            }
            if (argument == "--root") options.root = value;
            if (argument == "--references") options.references = value;
            if (argument == "--output") options.output = value;
            continue;
        }
        std::cerr << "Unknown or incomplete option: " << argument << '\n';
        return false;
    }
    return true;
}
#endif

bool make_directory_chain(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::size_t start = path.compare(0, 6, "sdmc:/") == 0 ? 6 : 0;
    if (!path.empty() && path[0] == '/' && start == 0) {
        start = 1;
    }
    for (std::size_t i = start; i <= path.size(); ++i) {
        if (i != path.size() && path[i] != '/') {
            continue;
        }
        if (i == 0 || (i == 5 && path.compare(0, 6, "sdmc:/") == 0)) {
            continue;
        }
        const std::string current = path.substr(0, i);
        if (current.empty() || current == "sdmc:") {
            continue;
        }
        if (mkdir(current.c_str(), 0777) != 0 && errno != EEXIST) {
            return false;
        }
        struct stat info {};
        if (lstat(current.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
            return false;
        }
    }
    return true;
}

#ifndef SWITCHSCAN_HORIZON
bool ensure_parent_directory(const std::string& file_path) {
    const std::size_t separator = file_path.find_last_of('/');
    if (separator == std::string::npos) {
        return true;
    }
    return make_directory_chain(file_path.substr(0, separator));
}
#endif

} // namespace

int main(int argc, char* argv[]) {
    switchscan::Logger logger(std::cerr);
    Options options;

#ifdef SWITCHSCAN_HORIZON
    (void)argc;
    (void)argv;
    options.root = "sdmc:/switch/SwitchSecurityResearch/input/";
    options.references =
        "sdmc:/switch/SwitchSecurityResearch/references.sha256";
    const Result sd_result = fsdevMountSdmc();
    const bool sd_mounted = R_SUCCEEDED(sd_result);
    if (!sd_mounted) {
        logger.log(switchscan::LogLevel::error,
                   "SD card is not accessible; no report was saved.");
        return 1;
    }
#else
    if (!parse_options(argc, argv, options)) {
        return argc > 1 && std::string(argv[1]) == "--help" ? 0 : 2;
    }
#endif

    try {
        switchscan::SystemInfo system;
        switchscan::InventoryReport inventory;
        const switchscan::LoadedReferences references =
            switchscan::load_reference_manifest(options.references);
        if (!references.loaded) {
            logger.log(switchscan::LogLevel::warning, references.error);
        }

        std::unique_ptr<switchscan::SystemInfoProvider> provider =
            switchscan::make_system_info_provider();
        switchscan::ScanEngine engine(logger);
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new switchscan::SystemInfoCheck(*provider, system)));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new switchscan::FileInventoryCheck(
                options.root, references.hashes, inventory, references.loaded,
                references.error)));

        switchscan::ScanReport report;
        report.checks = engine.run_all();
        report.system = system;
#ifdef SWITCHSCAN_HORIZON
        report.collector_type = "NRO";
        report.system.components.push_back(
            {"sdmc", "OK", "SD filesystem mounted by fsdevMountSdmc"});
#else
        report.collector_type = "PC_TEST";
#endif
        report.collector_version = SWITCHSCAN_VERSION;
        report.inventory = inventory;
        if (!references.loaded && !references.error.empty()) {
            report.errors.push_back({"reference_manifest", references.error});
        }
        if (report.system.firmware.status != "OK" &&
            !report.system.firmware.detail.empty()) {
            report.errors.push_back(
                {report.system.firmware.source, report.system.firmware.detail});
        }
        if (report.system.model.status != "OK" &&
            !report.system.model.detail.empty()) {
            report.errors.push_back(
                {report.system.model.source, report.system.model.detail});
        }
        for (const switchscan::ScanResult& check : report.checks) {
            if (check.status == switchscan::ScanStatus::inconclusive &&
                check.evidence.find("Control execution failed") == 0) {
                report.errors.push_back({check.control_id, check.evidence});
            }
        }
        switchscan::ReportExporter::finalize_id(report);

#ifdef SWITCHSCAN_HORIZON
        const std::string output_path =
            "sdmc:/rapports_SSR/report-" + report.report_id + ".json";
        if (!make_directory_chain("sdmc:/rapports_SSR")) {
            throw std::runtime_error(
                "Cannot create or verify sdmc:/rapports_SSR");
        }
        switchscan::ReportExporter::write_json(output_path, report);
        logger.log(switchscan::LogLevel::info,
                   "JSON report saved to " + output_path);
#else
        if (!ensure_parent_directory(options.output)) {
            throw std::runtime_error("Cannot create output directory");
        }
        switchscan::ReportExporter::write_json(options.output, report);
        logger.log(switchscan::LogLevel::info,
                   "Report saved to " + options.output);
#endif
    } catch (const std::exception& error) {
        logger.log(switchscan::LogLevel::error,
                   std::string("Fatal collection error: ") + error.what());
#ifdef SWITCHSCAN_HORIZON
        if (fsdevUnmountDevice("sdmc") != 0) {
            logger.log(switchscan::LogLevel::warning,
                       "Failed to unmount sdmc after collection failure");
        }
#endif
        return 1;
    }

#ifdef SWITCHSCAN_HORIZON
    if (fsdevUnmountDevice("sdmc") != 0) {
        logger.log(switchscan::LogLevel::warning,
                   "Failed to unmount sdmc after report generation");
    }
#endif
    return 0;
}
