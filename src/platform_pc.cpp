// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/platform.hpp"

namespace switchscan {
namespace {

class PcSystemInfoProvider final : public SystemInfoProvider {
public:
    SystemInfo collect() override {
        SystemInfo info;
        info.platform = "PC";
        info.runtime_environment.detail =
            "The PC test adapter cannot detect a Horizon runtime environment.";
        info.runtime_environment.source = "PC_TEST_ADAPTER";
        info.runtime_environment.limitations =
            "Synthetic host tests do not establish Switch environment state.";
        info.firmware.detail = "Horizon firmware is not present on PC";
        info.firmware.source = "PC_TEST_ADAPTER";
        info.installed_image_firmware.detail =
            "The PC test adapter does not inspect a Switch firmware image.";
        info.installed_image_firmware.source = "PC_TEST_ADAPTER";
        info.model.detail = "Nintendo Switch model is not present on PC";
        info.model.source = "PC_TEST_ADAPTER";
        return info;
    }
};

} // namespace

std::unique_ptr<SystemInfoProvider> make_system_info_provider() {
    return std::unique_ptr<SystemInfoProvider>(new PcSystemInfoProvider());
}

} // namespace switchscan
