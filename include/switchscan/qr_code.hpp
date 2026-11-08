#pragma once

#include <string>
#include <vector>

namespace switchscan {

class QrCode {
public:
    // Produces a QR Code Model 2, version 3-L (29x29), byte mode, up to 53 bytes.
    static QrCode encode(const std::string& text);
    int size() const noexcept;
    bool module(int x, int y) const;
    std::string to_svg(int quiet_zone = 4, int scale = 8) const;

private:
    int size_ = 29;
    std::vector<bool> modules_;
};

} // namespace switchscan
