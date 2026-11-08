CXX ?= g++
BUILD_DIR := build
CPPFLAGS := -Iinclude
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2
VERSION ?= development
VERSION_CPPFLAGS := -DSWITCHSCAN_VERSION='"$(VERSION)"'

CORE_SOURCES := \
	src/types.cpp \
	src/logger.cpp \
	src/scan_engine.cpp \
	src/json_exporter.cpp \
	src/sha256.cpp \
	src/inventory.cpp \
	src/system_info.cpp \
	src/report.cpp
APP_SOURCE := app/main.cpp
TEST_SOURCE := tests/test_scan_engine.cpp
PC_PLATFORM_SOURCE := src/platform_pc.cpp
SWITCH_PLATFORM_SOURCE := src/platform_horizon.cpp

PC_BINARY := $(BUILD_DIR)/switch_security_research
TEST_BINARY := $(BUILD_DIR)/test_scan_engine

.PHONY: all pc test switch clean

all: pc

pc: $(PC_BINARY)

$(BUILD_DIR):
	mkdir -p $@

$(PC_BINARY): $(CORE_SOURCES) $(PC_PLATFORM_SOURCE) $(APP_SOURCE) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(VERSION_CPPFLAGS) $(CXXFLAGS) $(CORE_SOURCES) $(PC_PLATFORM_SOURCE) $(APP_SOURCE) -o $@

$(TEST_BINARY): $(CORE_SOURCES) $(PC_PLATFORM_SOURCE) $(TEST_SOURCE) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(VERSION_CPPFLAGS) $(CXXFLAGS) $(CORE_SOURCES) $(PC_PLATFORM_SOURCE) $(TEST_SOURCE) -o $@

test: $(TEST_BINARY)
	./$(TEST_BINARY)

switch: | $(BUILD_DIR)
	@test -n "$(DEVKITPRO)" || (echo "DEVKITPRO is not set; install devkitPro/libnx first." >&2; exit 1)
	@test -x "$(DEVKITPRO)/devkitA64/bin/aarch64-none-elf-g++" || (echo "devkitA64 C++ compiler not found." >&2; exit 1)
	@test -x "$(DEVKITPRO)/tools/bin/elf2nro" || (echo "devkitPro elf2nro not found." >&2; exit 1)
	$(DEVKITPRO)/devkitA64/bin/aarch64-none-elf-g++ -Iinclude -I$(DEVKITPRO)/libnx/include -DSWITCHSCAN_HORIZON $(VERSION_CPPFLAGS) -std=c++17 -Wall -Wextra -O2 -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE -specs=$(DEVKITPRO)/libnx/switch.specs $(CORE_SOURCES) $(SWITCH_PLATFORM_SOURCE) $(APP_SOURCE) -L$(DEVKITPRO)/libnx/lib -lnx -o $(BUILD_DIR)/switch_security_research.elf
	$(DEVKITPRO)/tools/bin/elf2nro $(BUILD_DIR)/switch_security_research.elf $(BUILD_DIR)/switch_security_research.nro

clean:
	rm -f $(PC_BINARY) $(TEST_BINARY) $(BUILD_DIR)/switch_security_research.elf $(BUILD_DIR)/switch_security_research.nro
