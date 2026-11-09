// SPDX-License-Identifier: GPL-2.0-or-later
#include "switchscan/platform.hpp"

#include <switch.h>

#include <cstdio>

namespace switchscan {
namespace {

class HorizonSystemInfoProvider final : public SystemInfoProvider {
public:
    SystemInfo collect() override {
        SystemInfo info;
        info.platform = "Nintendo Switch / Horizon";
        const bool atmosphere_detected = hosversionIsAtmosphere();
        info.runtime_environment.status =
            atmosphere_detected
                ? RuntimeEnvironmentStatus::cfw_detected
                : RuntimeEnvironmentStatus::modified_or_unknown;
        info.runtime_environment.confidence =
            atmosphere_detected ? DetectionConfidence::high
                                : DetectionConfidence::unknown;
        info.runtime_environment.source = "libnx:hosversionIsAtmosphere";
        info.runtime_environment.detail =
            atmosphere_detected
                ? "libnx reports that the running Horizon environment is "
                  "augmented by Atmosphere."
                : "No affirmative Atmosphere signal was reported; stock "
                  "Horizon is not confirmed.";
        info.runtime_environment.limitations =
            "This signal detects Atmosphere only. A negative result does not "
            "prove stock state or exclude other modifications/CFW. The API "
            "does not report hardware revision.";
        info.installed_image_firmware.status = "NOT_ACCESSIBLE";
        info.installed_image_firmware.source = "NRO_SCOPE";
        info.installed_image_firmware.detail =
            "The NRO does not inspect the SYSTEM partition or an installed "
            "firmware image.";

        const Result init_result = setsysInitialize();
        if (R_FAILED(init_result)) {
            info.firmware.detail = "setsysInitialize failed: " +
                                   std::to_string(init_result);
            info.model.detail = info.firmware.detail;
            info.components.push_back(
                {"set:sys", "NOT_ACCESSIBLE", info.firmware.detail});
            info.firmware.source = "set:sys";
            info.model.source = "set:sys";
            return info;
        }
        info.components.push_back(
            {"set:sys", "OK", "Service initialization succeeded"});

        SetSysFirmwareVersion firmware{};
        const Result firmware_result = setsysGetFirmwareVersion(&firmware);
        if (R_SUCCEEDED(firmware_result)) {
            char version[32]{};
            std::snprintf(version, sizeof(version), "%u.%u.%u",
                          static_cast<unsigned int>(firmware.major),
                          static_cast<unsigned int>(firmware.minor),
                          static_cast<unsigned int>(firmware.micro));
            info.firmware.value = version;
            info.firmware.status = "OK";
            info.firmware.detail = "Reported by set:sys";
            info.firmware.source = "set:sys";
        } else {
            info.firmware.detail = "setsysGetFirmwareVersion failed: " +
                                   std::to_string(firmware_result);
            info.firmware.source = "set:sys";
        }

        SetSysProductModel model = SetSysProductModel_Invalid;
        const Result model_result = setsysGetProductModel(&model);
        if (R_SUCCEEDED(model_result)) {
            info.model.value = std::to_string(static_cast<int>(model));
            info.model.status = "OK";
            info.model.detail = "Numeric SetSysProductModel returned by set:sys";
            info.model.source = "set:sys";
        } else {
            info.model.detail = "setsysGetProductModel failed: " +
                                std::to_string(model_result);
            info.model.source = "set:sys";
        }

        setsysExit();
        return info;
    }
};

} // namespace

std::unique_ptr<SystemInfoProvider> make_system_info_provider() {
    return std::unique_ptr<SystemInfoProvider>(new HorizonSystemInfoProvider());
}

} // namespace switchscan
