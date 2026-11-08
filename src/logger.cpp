#include "switchscan/logger.hpp"

#include "switchscan/types.hpp"

#include <ostream>

namespace switchscan {
namespace {

const char* to_string(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::info: return "INFO";
    case LogLevel::warning: return "WARNING";
    case LogLevel::error: return "ERROR";
    }
    return "INFO";
}

} // namespace

Logger::Logger(std::ostream& output) : output_(output) {}

void Logger::log(LogLevel level, const std::string& message) {
    output_ << current_timestamp_utc() << " [" << to_string(level) << "] "
            << message << '\n';
}

} // namespace switchscan
