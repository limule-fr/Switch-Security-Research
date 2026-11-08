// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#ifdef SWITCHSCAN_HORIZON
extern "C" {
#include <switch/crypto/sha256.h>
}
#endif

namespace switchscan {

class Sha256 {
public:
    Sha256();
    void update(const void* data, std::size_t size);
    std::array<std::uint8_t, 32> finish();
    static std::string to_hex(const std::array<std::uint8_t, 32>& digest);

private:
    void transform(const std::uint8_t* block);
    std::array<std::uint32_t, 8> state_;
    std::array<std::uint8_t, 64> buffer_;
    std::uint64_t total_bytes_;
    std::size_t buffered_;
    bool finished_;
#ifdef SWITCHSCAN_HORIZON
    Sha256Context horizon_context_;
#endif
};

} // namespace switchscan
