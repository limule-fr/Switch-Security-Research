#pragma once

#include "switchscan/system_info.hpp"

#include <memory>

namespace switchscan {

std::unique_ptr<SystemInfoProvider> make_system_info_provider();

} // namespace switchscan
