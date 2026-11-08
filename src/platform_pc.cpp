#include "switchscan/platform.hpp"

namespace switchscan {
namespace {

class PcSystemInfoProvider final : public SystemInfoProvider {
public:
    SystemInfo collect() override {
        SystemInfo info;
        info.platform = "PC";
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
