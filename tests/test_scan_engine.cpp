// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/json_exporter.hpp"
#include "switchscan/inventory.hpp"
#include "switchscan/report.hpp"
#include "switchscan/scan_engine.hpp"
#include "switchscan/sha256.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class FixedCheck final : public switchscan::ScanCheck {
public:
    FixedCheck(std::string id, switchscan::CheckOutcome outcome)
        : metadata_{std::move(id), "Test control", "Test description",
                    switchscan::Severity::high},
          outcome_(std::move(outcome)) {}

    const switchscan::CheckMetadata& metadata() const noexcept override {
        return metadata_;
    }

    switchscan::CheckOutcome run() override {
        return outcome_;
    }

private:
    switchscan::CheckMetadata metadata_;
    switchscan::CheckOutcome outcome_;
};

class ThrowingCheck final : public switchscan::ScanCheck {
public:
    ThrowingCheck()
        : metadata_{"test.throw", "Throwing control", "Failure isolation test",
                    switchscan::Severity::medium} {}

    const switchscan::CheckMetadata& metadata() const noexcept override {
        return metadata_;
    }

    switchscan::CheckOutcome run() override {
        throw std::runtime_error("simulated failure");
    }

private:
    switchscan::CheckMetadata metadata_;
};

} // namespace

int main() {
    try {
        std::ostringstream log_output;
        switchscan::Logger logger(log_output);
        switchscan::ScanEngine engine(logger);
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(new FixedCheck(
            "test.vulnerable-without-proof",
            {switchscan::ScanStatus::vulnerable, "", false})));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new ThrowingCheck()));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(new FixedCheck(
            "test.confirmed-with-proof",
            {switchscan::ScanStatus::vulnerable, "Synthetic test evidence",
             true})));
        engine.add_check(std::unique_ptr<switchscan::ScanCheck>(new FixedCheck(
            "test.empty-proof",
            {switchscan::ScanStatus::vulnerable, "", true})));

        const std::vector<switchscan::ScanResult> results = engine.run_all();
        require(results.size() == 4, "All independent controls must be run");
        require(results[0].status == switchscan::ScanStatus::suspect,
                "VULNERABLE without proof must be downgraded");
        require(results[1].status == switchscan::ScanStatus::inconclusive,
                "A failed control must be inconclusive");
        require(results[2].status == switchscan::ScanStatus::vulnerable,
                "A finding with explicit sufficient evidence should be retained");
        require(results[3].status == switchscan::ScanStatus::suspect,
                "A finding without evidence must be downgraded");
        require(!results[0].timestamp_utc.empty(),
                "Results must carry a UTC timestamp");
        require(log_output.str().find("simulated failure") != std::string::npos,
                "Control failures must be logged");

        const std::string json = switchscan::JsonExporter::to_json(results);
        require(json.find("\"status\": \"SUSPECT\"") != std::string::npos,
                "JSON must contain the downgraded status");
        require(json.find("\"evidence_sufficient\": true") != std::string::npos,
                "JSON must include evidence sufficiency");
        require(json.find("\"confidence\"") == std::string::npos,
                "JSON must not imply an undefined confidence methodology");

        switchscan::ScanResult escaped;
        escaped.control_id = "test.escape";
        escaped.evidence = "quote: \" slash: \\ newline:\n";
        const std::string escaped_json = switchscan::JsonExporter::to_json({escaped});
        require(escaped_json.find("quote: \\\" slash: \\\\ newline:\\n") !=
                    std::string::npos,
                "JSON strings must escape quotes, backslashes, and newlines");

        bool duplicate_rejected = false;
        switchscan::ScanEngine duplicate_engine(logger);
        duplicate_engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
            new FixedCheck("duplicate", {})));
        try {
            duplicate_engine.add_check(std::unique_ptr<switchscan::ScanCheck>(
                new FixedCheck("duplicate", {})));
        } catch (const std::invalid_argument&) {
            duplicate_rejected = true;
        }
        require(duplicate_rejected, "Duplicate control IDs must be rejected");

        switchscan::Sha256 sha;
        sha.update("a", 1);
        sha.update("bc", 2);
        require(switchscan::Sha256::to_hex(sha.finish()) ==
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "SHA-256 must match the standard abc test vector");

        char temp_template[] = "build/switchscan-test-XXXXXX";
        char* temp_dir = mkdtemp(temp_template);
        require(temp_dir != nullptr, "A temporary test directory is required");
        const std::string base(temp_dir);
        const std::string input_dir = base + "/input";
        const std::string file_path = input_dir + "/sample.txt";
        const std::string manifest_path = base + "/references.sha256";
        require(mkdir(input_dir.c_str(), 0700) == 0,
                "Test input directory must be created");
        {
            std::ofstream file(file_path.c_str(), std::ios::binary);
            file << "abc";
            require(static_cast<bool>(file), "Test file must be written");
        }
        {
            std::ofstream manifest(manifest_path.c_str());
            manifest << "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        " sample.txt\n";
            require(static_cast<bool>(manifest), "Reference manifest must be written");
        }
        const switchscan::LoadedReferences loaded =
            switchscan::load_reference_manifest(manifest_path);
        require(loaded.loaded && loaded.hashes.size() == 1,
                "Valid SHA-256 reference manifests must load");
        switchscan::InventoryReport inventory;
        switchscan::FileInventoryCheck inventory_check(
            input_dir, loaded.hashes, inventory, loaded.loaded, loaded.error);
        const switchscan::CheckOutcome matched = inventory_check.run();
        require(matched.status == switchscan::ScanStatus::ok &&
                    inventory.analyzed_count == 1 &&
                    inventory.resources[0].reference ==
                        switchscan::ReferenceState::match,
                "Inventory should verify matching references");

        switchscan::FileInventoryCheck mismatch_check(
            input_dir, {{"sample.txt", std::string(64, '0')}}, inventory,
            true, "");
        const switchscan::CheckOutcome mismatch = mismatch_check.run();
        require(mismatch.status == switchscan::ScanStatus::suspect &&
                    inventory.mismatch_count == 1 &&
                    inventory.resources[0].state ==
                        switchscan::ResourceState::analyzed,
                "Reference differences must be reported as suspect integrity "
                "anomalies");

        switchscan::FileInventoryCheck inaccessible_check(
            base + "/missing", {}, inventory, false, "manifest unavailable");
        const switchscan::CheckOutcome inaccessible =
            inaccessible_check.run();
        require(inaccessible.status == switchscan::ScanStatus::not_accessible &&
                    inventory.inaccessible_count == 1,
                "Unavailable roots must not be reported as clean");

        switchscan::ScanReport report;
        report.collector_type = "NRO";
        report.collector_version = "test";
        report.system.platform = "Nintendo Switch / Horizon";
        report.system.firmware = {"23.0.1", "OK", "test fixture", "set:sys"};
        report.system.installed_image_firmware = {
            "", "NOT_ACCESSIBLE", "Not inspected by NRO", "NRO_SCOPE"};
        report.inventory = inventory;
        switchscan::ReportExporter::finalize_id(report);
        switchscan::ScanReport second_report = report;
        switchscan::ReportExporter::finalize_id(second_report);
        require(report.report_id.size() == 64 &&
                    second_report.report_id != report.report_id,
                "Report identifiers must be full-length and distinct");
        const std::string report_json =
            switchscan::ReportExporter::to_json(report);
        require(report_json.find("\"schema_version\": 1") != std::string::npos &&
                    report_json.find("\"report_id\": \"" + report.report_id +
                                     "\"") != std::string::npos &&
                    report_json.find("\"collected_at_utc\"") !=
                        std::string::npos &&
                    report_json.find("\"collector_type\": \"NRO\"") !=
                        std::string::npos &&
                    report_json.find("\"collector_version\": \"test\"") !=
                        std::string::npos &&
                    report_json.find("\"running_os\"") != std::string::npos &&
                    report_json.find("\"installed_image\"") !=
                        std::string::npos &&
                    report_json.find("\"inaccessible_resources\"") !=
                        std::string::npos &&
                    report_json.find("\"errors\"") != std::string::npos,
                "JSON report must include the required schema fields");
        require(report_json.find("\"value\": null") != std::string::npos,
                "Inaccessible firmware values must be null");
        require(report_json.find("\"resource\": \"firmware.installed_image\"") !=
                    std::string::npos,
                "The uncollected installed image must be explicitly inaccessible");
        require(report_json.find("\"confidence\"") == std::string::npos &&
                    report_json.find("\"qr_payload\"") == std::string::npos,
                "Report must not include undefined confidence or QR payload");

        const std::string reports_dir = base + "/reports";
        require(mkdir(reports_dir.c_str(), 0700) == 0,
                "Test report directory must be created");
        const std::string report_path = reports_dir + "/report.json";
        switchscan::ReportExporter::write_json(report_path, report);
        std::ifstream saved_report(report_path.c_str(), std::ios::binary);
        const std::string saved_contents((std::istreambuf_iterator<char>(
                                              saved_report)),
                                         std::istreambuf_iterator<char>());
        require(saved_contents == report_json,
                "The saved report must match the standalone JSON output");

        bool existing_report_rejected = false;
        try {
            switchscan::ReportExporter::write_json(report_path, report);
        } catch (const std::runtime_error&) {
            existing_report_rejected = true;
        }
        require(existing_report_rejected,
                "An existing report must never be overwritten");
        require(access((report_path + ".tmp-" + report.report_id).c_str(),
                       F_OK) != 0,
                "Temporary report must be cleaned after a name collision");
        std::ifstream unchanged_report(report_path.c_str(), std::ios::binary);
        const std::string unchanged_contents((std::istreambuf_iterator<char>(
                                                  unchanged_report)),
                                             std::istreambuf_iterator<char>());
        require(unchanged_contents == saved_contents,
                "A failed duplicate write must preserve the existing report");

        bool write_error_reported = false;
        try {
            switchscan::ReportExporter::write_json(
                base + "/missing/output.json", report);
        } catch (const std::runtime_error&) {
            write_error_reported = true;
        }
        require(write_error_reported,
                "An unavailable output directory must report a write failure");
        require(access((base + "/missing/output.json.tmp-" + report.report_id)
                           .c_str(),
                       F_OK) != 0,
                "Temporary report must be cleaned after an output error");

        unlink(file_path.c_str());
        unlink(manifest_path.c_str());
        unlink(report_path.c_str());
        rmdir(reports_dir.c_str());
        rmdir(input_dir.c_str());
        rmdir(base.c_str());

        std::cout << "All scanner core tests passed.\n";
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
