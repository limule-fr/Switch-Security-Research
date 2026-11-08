#include "switchscan/qr_code.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace switchscan {
namespace {

constexpr int kSize = 29;
constexpr std::size_t kDataCodewords = 55;
constexpr std::size_t kEccCodewords = 15;

std::uint8_t gf_multiply(std::uint8_t x, std::uint8_t y) {
    std::uint8_t result = 0;
    for (int i = 7; i >= 0; --i) {
        result = static_cast<std::uint8_t>((result << 1) ^ ((result >> 7) * 0x1d));
        result ^= static_cast<std::uint8_t>(((y >> i) & 1) * x);
    }
    return result;
}

std::vector<std::uint8_t> reed_solomon_remainder(
    const std::vector<std::uint8_t>& data, std::size_t degree) {
    std::vector<std::uint8_t> divisor(degree);
    divisor.back() = 1;
    std::uint8_t root = 1;
    for (std::size_t i = 0; i < degree; ++i) {
        for (std::size_t j = 0; j < degree; ++j) {
            divisor[j] = gf_multiply(divisor[j], root);
            if (j + 1 < degree) {
                divisor[j] ^= divisor[j + 1];
            }
        }
        root = gf_multiply(root, 2);
    }

    std::vector<std::uint8_t> remainder(degree);
    for (std::uint8_t value : data) {
        const std::uint8_t factor = value ^ remainder.front();
        std::move(remainder.begin() + 1, remainder.end(), remainder.begin());
        remainder.back() = 0;
        for (std::size_t i = 0; i < degree; ++i) {
            remainder[i] ^= gf_multiply(divisor[i], factor);
        }
    }
    return remainder;
}

void append_bits(std::vector<bool>& bits, unsigned int value, int count) {
    for (int i = count - 1; i >= 0; --i) {
        bits.push_back(((value >> i) & 1U) != 0);
    }
}

} // namespace

QrCode QrCode::encode(const std::string& text) {
    if (text.size() > 53) {
        throw std::invalid_argument("QR version 3-L supports at most 53 bytes");
    }

    std::vector<bool> bits;
    bits.reserve(kDataCodewords * 8);
    append_bits(bits, 0x4, 4);
    append_bits(bits, static_cast<unsigned int>(text.size()), 8);
    for (const unsigned char character : text) {
        append_bits(bits, character, 8);
    }
    const std::size_t capacity = kDataCodewords * 8;
    const std::size_t terminator = std::min<std::size_t>(4, capacity - bits.size());
    bits.insert(bits.end(), terminator, false);
    while (bits.size() % 8 != 0) {
        bits.push_back(false);
    }

    std::vector<std::uint8_t> data;
    data.reserve(kDataCodewords);
    for (std::size_t i = 0; i < bits.size(); i += 8) {
        std::uint8_t byte = 0;
        for (std::size_t j = 0; j < 8; ++j) {
            byte = static_cast<std::uint8_t>(
                (byte << 1) | (bits[i + j] ? 1 : 0));
        }
        data.push_back(byte);
    }
    for (std::uint8_t pad = 0xec; data.size() < kDataCodewords;
         pad = pad == 0xec ? 0x11 : 0xec) {
        data.push_back(pad);
    }

    std::vector<std::uint8_t> codewords = data;
    const auto ecc = reed_solomon_remainder(data, kEccCodewords);
    codewords.insert(codewords.end(), ecc.begin(), ecc.end());
    std::vector<bool> codeword_bits;
    codeword_bits.reserve(codewords.size() * 8);
    for (std::uint8_t byte : codewords) {
        append_bits(codeword_bits, byte, 8);
    }

    QrCode qr;
    qr.modules_.assign(kSize * kSize, false);
    std::vector<bool> function(kSize * kSize, false);
    auto set_function = [&](int x, int y, bool dark) {
        if (x >= 0 && x < kSize && y >= 0 && y < kSize) {
            qr.modules_[y * kSize + x] = dark;
            function[y * kSize + x] = true;
        }
    };

    auto finder = [&](int center_x, int center_y) {
        for (int dy = -1; dy <= 7; ++dy) {
            for (int dx = -1; dx <= 7; ++dx) {
                const int x = center_x + dx;
                const int y = center_y + dy;
                const bool inside = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6;
                const bool dark = inside &&
                                  (dx == 0 || dx == 6 || dy == 0 || dy == 6 ||
                                   (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
                set_function(x, y, dark);
            }
        }
    };
    finder(0, 0);
    finder(kSize - 7, 0);
    finder(0, kSize - 7);

    for (int i = 8; i < kSize - 8; ++i) {
        set_function(i, 6, i % 2 == 0);
        set_function(6, i, i % 2 == 0);
    }
    for (int dy = -2; dy <= 2; ++dy) {
        for (int dx = -2; dx <= 2; ++dx) {
            const int distance = std::max(std::abs(dx), std::abs(dy));
            set_function(22 + dx, 22 + dy, distance != 1);
        }
    }
    for (int i = 0; i <= 5; ++i) set_function(8, i, false);
    set_function(8, 7, false);
    set_function(8, 8, false);
    set_function(7, 8, false);
    for (int i = 9; i < 15; ++i) set_function(14 - i, 8, false);
    for (int i = 0; i < 8; ++i) set_function(kSize - 1 - i, 8, false);
    for (int i = 8; i < 15; ++i) {
        set_function(8, kSize - 15 + i, false);
    }

    std::size_t bit_index = 0;
    bool upward = true;
    for (int right = kSize - 1; right >= 1; right -= 2) {
        if (right == 6) {
            right = 5;
        }
        for (int vertical = 0; vertical < kSize; ++vertical) {
            const int y = upward ? kSize - 1 - vertical : vertical;
            for (int offset = 0; offset < 2; ++offset) {
                const int x = right - offset;
                const int index = y * kSize + x;
                if (!function[index]) {
                    bool dark = bit_index < codeword_bits.size()
                                    ? codeword_bits[bit_index++]
                                    : false;
                    if ((x + y) % 2 == 0) {
                        dark = !dark;
                    }
                    qr.modules_[index] = dark;
                }
            }
        }
        upward = !upward;
    }

    const unsigned int format_data = (1U << 3); // Error correction level L, mask 0.
    unsigned int remainder = format_data;
    for (int i = 0; i < 10; ++i) {
        remainder = (remainder << 1) ^
                    (((remainder >> 9) & 1U) ? 0x537U : 0U);
    }
    const unsigned int format = ((format_data << 10) | remainder) ^ 0x5412U;
    auto set_format = [&](int x, int y, int bit) {
        set_function(x, y, ((format >> bit) & 1U) != 0);
    };
    for (int i = 0; i <= 5; ++i) set_format(8, i, i);
    set_format(8, 7, 6);
    set_format(8, 8, 7);
    set_format(7, 8, 8);
    for (int i = 9; i < 15; ++i) set_format(14 - i, 8, i);
    for (int i = 0; i < 8; ++i) set_format(kSize - 1 - i, 8, i);
    for (int i = 8; i < 15; ++i) set_format(8, kSize - 15 + i, i);
    set_function(8, kSize - 8, true);

    return qr;
}

int QrCode::size() const noexcept {
    return size_;
}

bool QrCode::module(int x, int y) const {
    if (x < 0 || x >= size_ || y < 0 || y >= size_) {
        throw std::out_of_range("QR module coordinates are out of range");
    }
    return modules_[y * size_ + x];
}

std::string QrCode::to_svg(int quiet_zone, int scale) const {
    if (quiet_zone < 0 || scale <= 0) {
        throw std::invalid_argument("Invalid QR SVG dimensions");
    }
    const int extent = (size_ + quiet_zone * 2) * scale;
    std::ostringstream svg;
    svg << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << extent
        << "\" height=\"" << extent << "\" viewBox=\"0 0 " << extent << ' '
        << extent << "\">\n<rect width=\"100%\" height=\"100%\" fill=\"#fff\"/>"
        << "\n<path fill=\"#000\" d=\"";
    for (int y = 0; y < size_; ++y) {
        for (int x = 0; x < size_; ++x) {
            if (module(x, y)) {
                svg << 'M' << (x + quiet_zone) * scale << ' '
                    << (y + quiet_zone) * scale << "h" << scale << 'v' << scale
                    << "h-" << scale << 'z';
            }
        }
    }
    svg << "\"/>\n</svg>\n";
    return svg.str();
}

} // namespace switchscan
