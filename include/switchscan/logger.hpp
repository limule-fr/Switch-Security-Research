#pragma once

#include <iosfwd>
#include <string>

namespace switchscan {

enum class LogLevel {
    info,
    warning,
    error
};

// The engine runs checks sequentially, so the logger does not require locking.
class Logger {
public:
    explicit Logger(std::ostream& output);
    void log(LogLevel level, const std::string& message);

private:
    std::ostream& output_;
};

} // namespace switchscan
