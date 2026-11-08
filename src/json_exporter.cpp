// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/json_exporter.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace switchscan {
namespace {

void write_escaped(std::ostream& output, const std::string& value) {
    output << '"';
    for (const unsigned char character : value) {
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (character < 0x20) {
                output << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << static_cast<int>(character)
                       << std::dec << std::setfill(' ');
            } else {
                output << static_cast<char>(character);
            }
        }
    }
    output << '"';
}

} // namespace

std::string JsonExporter::to_json(const std::vector<ScanResult>& results) {
    std::ostringstream output;
    output << "{\n  \"results\": [";

    for (std::size_t index = 0; index < results.size(); ++index) {
        const ScanResult& result = results[index];
        output << (index == 0 ? "\n" : ",\n") << "    {\n"
               << "      \"control_id\": ";
        write_escaped(output, result.control_id);
        output << ",\n      \"analysis_name\": ";
        write_escaped(output, result.analysis_name);
        output << ",\n      \"description\": ";
        write_escaped(output, result.description);
        output << ",\n      \"severity\": ";
        write_escaped(output, to_string(result.severity));
        output << ",\n      \"status\": ";
        write_escaped(output, to_string(result.status));
        output << ",\n      \"evidence\": ";
        write_escaped(output, result.evidence);
        output << ",\n      \"evidence_sufficient\": "
               << (result.evidence_sufficient ? "true" : "false")
               << ",\n      \"timestamp_utc\": ";
        write_escaped(output, result.timestamp_utc);
        output << "\n    }";
    }

    if (!results.empty()) {
        output << '\n';
    }
    output << "  ]\n}\n";
    return output.str();
}

void JsonExporter::write_file(const std::string& path,
                              const std::vector<ScanResult>& results) {
    std::ofstream output(path.c_str(), std::ios::out | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Cannot open JSON output file: " + path);
    }
    output << to_json(results);
    if (!output) {
        throw std::runtime_error("Failed to write JSON output file: " + path);
    }
}

} // namespace switchscan
