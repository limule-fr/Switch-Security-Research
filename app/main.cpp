// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/inventory.hpp"
#include "switchscan/platform.hpp"
#include "switchscan/research_module.hpp"
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

#ifdef SWITCHSCAN_HORIZON
void show_diagnostic(PrintConsole* console, const char* message) {
    std::printf("%s\n", message);
    consoleUpdate(console);
}

void wait_for_diagnostic_button(PrintConsole* console, PadState& pad) {
    std::printf("\nPress any controller button to exit.\n");
    consoleUpdate(console);
    while (appletMainLoop()) {
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) != 0) {
            break;
        }
        consoleUpdate(console);
    }
}
#endif

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
#ifdef SWITCHSCAN_HORIZON
    PrintConsole* diagnostic_console = consoleInit(nullptr);
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState diagnostic_pad{};
    padInitializeDefault(&diagnostic_pad);
    show_diagnostic(diagnostic_console,
                    "[SSR TEMPORARY DIAGNOSTIC] main() reached");
    show_diagnostic(diagnostic_console, "Initialization");
#endif
    switchscan::Logger logger(std::cerr);
    Options options;

#ifdef SWITCHSCAN_HORIZON
    (void)argc;
    (void)argv;
    options.root = "sdmc:/switch/SwitchSecurityResearch/input/";
    options.references =
        "sdmc:/switch/SwitchSecurityResearch/references.sha256";
    show_diagnostic(diagnostic_console, "Checking SD device...");
    FsFileSystem* sd_filesystem = fsdevGetDeviceFileSystem("sdmc");
    Result sd_mount_result = 0;
    if (sd_filesystem != nullptr) {
        show_diagnostic(diagnostic_console,
                        "SD device is already mounted; reusing it.");
    } else {
        show_diagnostic(diagnostic_console,
                        "SD device is not mounted; attempting fallback mount...");
        sd_mount_result = fsdevMountSdmc();
        std::printf("fsdevMountSdmc result: %u (0x%08X)\n",
                    static_cast<unsigned int>(sd_mount_result),
                    static_cast<unsigned int>(sd_mount_result));
        consoleUpdate(diagnostic_console);
        sd_filesystem = fsdevGetDeviceFileSystem("sdmc");
    }
    if (sd_filesystem == nullptr) {
        const Result sd_last_result = fsdevGetLastResult();
        std::printf("SD device unavailable after mount check.\n"
                    "Mount result: %u (0x%08X)\n"
                    "Last fsdev result: %u (0x%08X)\n",
                    static_cast<unsigned int>(sd_mount_result),
                    static_cast<unsigned int>(sd_mount_result),
                    static_cast<unsigned int>(sd_last_result),
                    static_cast<unsigned int>(sd_last_result));
        consoleUpdate(diagnostic_console);
        logger.log(switchscan::LogLevel::error,
                   "SD card is not accessible; no report was saved.");
        show_diagnostic(diagnostic_console,
                        "SD device is unavailable; no report was saved.");
        wait_for_diagnostic_button(diagnostic_console, diagnostic_pad);
        return 1;
    }
    show_diagnostic(diagnostic_console, "SD device is available.");
#else
    if (!parse_options(argc, argv, options)) {
        return argc > 1 && std::string(argv[1]) == "--help" ? 0 : 2;
    }
#endif

    try {
        switchscan::SystemInfo system;
        switchscan::InventoryReport inventory;
#ifdef SWITCHSCAN_HORIZON
        show_diagnostic(diagnostic_console, "Loading reference manifest...");
#endif
        const switchscan::LoadedReferences references =
            switchscan::load_reference_manifest(options.references);
        if (!references.loaded) {
            logger.log(switchscan::LogLevel::warning, references.error);
        }
#ifdef SWITCHSCAN_HORIZON
        show_diagnostic(diagnostic_console,
                        references.loaded ? "Manifest loaded."
                                          : "Manifest unavailable; continuing.");
#endif

        std::unique_ptr<switchscan::SystemInfoProvider> provider =
            switchscan::make_system_info_provider();
        switchscan::ScanEngine engine(logger);
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new switchscan::SystemInfoCheck(*provider, system)));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new switchscan::FileInventoryCheck(
                options.root, references.hashes, inventory, references.loaded,
                references.error, options.references)));

        switchscan::ModuleRegistry module_registry;
        for (auto& module : switchscan::make_default_research_modules()) {
            module_registry.add_module(std::move(module));
        }
#ifdef SWITCHSCAN_HORIZON
        const switchscan::ScanPlatform scan_platform =
            switchscan::ScanPlatform::horizon;
#else
        const switchscan::ScanPlatform scan_platform =
            switchscan::ScanPlatform::pc_test;
#endif
#ifdef SWITCHSCAN_HORIZON
        show_diagnostic(diagnostic_console, "Collection started.");
#endif
        const switchscan::ModuleRunReport module_report =
            module_registry.run_all(scan_platform, logger);

        switchscan::ScanReport report;
        report.checks = engine.run_all();
        report.checks.insert(report.checks.end(), module_report.checks.begin(),
                             module_report.checks.end());
        report.modules = module_report.modules;
        for (const switchscan::ModuleExecutionError& error :
             module_report.errors) {
            report.errors.push_back(
                {"module:" + error.module_id + "/" + error.control_id,
                 error.message});
        }
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
        show_diagnostic(diagnostic_console, "Collection finished.");
#endif

#ifdef SWITCHSCAN_HORIZON
        const std::string output_path =
            "sdmc:/rapports_SSR/report-" + report.report_id + ".json";
        show_diagnostic(diagnostic_console,
                        "Creating report directory...");
        if (!make_directory_chain("sdmc:/rapports_SSR")) {
            throw std::runtime_error(
                "Cannot create or verify sdmc:/rapports_SSR");
        }
        show_diagnostic(diagnostic_console, "Writing JSON report...");
        switchscan::ReportExporter::write_json(output_path, report);
        logger.log(switchscan::LogLevel::info,
                   "JSON report saved to " + output_path);
        std::printf("Report created:\n%s\n", output_path.c_str());
        wait_for_diagnostic_button(diagnostic_console, diagnostic_pad);
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
        std::printf("FATAL ERROR:\n%s\n", error.what());
        wait_for_diagnostic_button(diagnostic_console, diagnostic_pad);
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
