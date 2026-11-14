# EntryNav2-CarPlay Makefile
# Designed for both Windows/Linux host testing (-std=gnu++0x) and HU_ENTRYNAV2 ARMv7 cross-builds.
# Valid for GNU Make 3.82 .. 4.4; recipes are POSIX sh.
#
# Sources and tests are auto-discovered:
#   * every src/core/*.cpp is compiled into libcarplay_core.a (pure, OS-agnostic)
#   * every src/platform/*.cpp is compiled into libcarplay_platform.a (sockets, reactor, files, RNG)
#   * src/platform/evo/*.cpp (vehicle-only HAL) is added to libcarplay_platform.a ONLY with EVO=1 and
#     TARGET_OS=linux; never on Windows
#   * every tests/test_*.cpp becomes its own binary $(BUILD_DIR)/test_<name>$(BIN_EXT), linked with
#     the platform library, then the core library (platform depends on core, and a static link needs
#     the dependent archive first), then $(SYS_LIBS)
# `make test-host` builds and runs all test binaries and fails if any one fails.
#
# Typical invocations:
#   make test-host BIN_EXT=.exe                 # Windows (w64devkit)
#   make test-host                              # Linux host / CI (CXX=... CXXFLAGS=... may be passed)
#   make arm-core | make arm-platform           # HU_ENTRYNAV2 cross build (arm-linux-gnueabihf-*)

CXX ?= g++
CC  ?= gcc
AR  ?= ar

COMMON_WARN := -Wall -Wextra -Werror
CXXFLAGS ?= -std=gnu++0x -O2 $(COMMON_WARN)
CFLAGS   ?= -std=c99 -O2 -Wall -Wextra
CPPFLAGS := -Iinclude -Ithird_party/monocypher
TEST_CPPFLAGS := $(CPPFLAGS) -Itests
# Per-object header dependency tracking (kept out of CXXFLAGS so overrides like arm-core keep it).
DEPFLAGS = -MMD -MP -MF $(@:.o=.d)

BUILD_DIR ?= build/host
BIN_EXT   ?=

# Target operating system of the build (decides system libraries and vehicle sources).
ifeq ($(OS),Windows_NT)
TARGET_OS ?= windows
else
TARGET_OS ?= linux
endif

ifeq ($(TARGET_OS),windows)
SYS_LIBS ?= -lws2_32 -lbcrypt
else
SYS_LIBS ?= -lpthread -lrt -ldl
endif

EVO ?= 0

CORE_CPP_SRCS := $(sort $(wildcard src/core/*.cpp))

MONO_C_SRCS := \
	third_party/monocypher/monocypher.c \
	third_party/monocypher/monocypher-ed25519.c

CORE_OBJS := \
	$(patsubst src/core/%.cpp,$(BUILD_DIR)/core_%.o,$(CORE_CPP_SRCS)) \
	$(patsubst third_party/monocypher/%.c,$(BUILD_DIR)/mono_%.o,$(MONO_C_SRCS))

CORE_LIB := $(BUILD_DIR)/libcarplay_core.a

PLATFORM_CPP_SRCS := $(sort $(wildcard src/platform/*.cpp))
EVO_CPP_SRCS :=
ifeq ($(EVO),1)
ifeq ($(TARGET_OS),linux)
EVO_CPP_SRCS := $(sort $(wildcard src/platform/evo/*.cpp))
else
$(warning EVO=1 ignored: vehicle sources are only built for TARGET_OS=linux)
endif
endif

PLATFORM_OBJS := \
	$(patsubst src/platform/%.cpp,$(BUILD_DIR)/plat_%.o,$(PLATFORM_CPP_SRCS)) \
	$(patsubst src/platform/evo/%.cpp,$(BUILD_DIR)/evo_%.o,$(EVO_CPP_SRCS))

PLATFORM_LIB := $(BUILD_DIR)/libcarplay_platform.a

PUBLIC_HDRS := $(wildcard include/carplay/*.hpp) $(wildcard include/carplay/platform/*.hpp)
TEST_HDRS   := $(wildcard tests/*.hpp)

TEST_SRCS := $(sort $(wildcard tests/test_*.cpp))
TEST_BINS := $(patsubst tests/%.cpp,$(BUILD_DIR)/%$(BIN_EXT),$(TEST_SRCS))

.PHONY: all core platform tests test-host clean arm-core arm-platform

all: test-host

core: $(CORE_LIB)

platform: $(PLATFORM_LIB) $(CORE_LIB)

tests: $(TEST_BINS)

$(CORE_LIB): $(CORE_OBJS)
	$(AR) rcs $@ $^

$(PLATFORM_LIB): $(PLATFORM_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD_DIR)/core_%.o: src/core/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/plat_%.o: src/platform/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/evo_%.o: src/platform/evo/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/mono_%.o: third_party/monocypher/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%$(BIN_EXT): tests/test_%.cpp $(PLATFORM_LIB) $(CORE_LIB) $(PUBLIC_HDRS) $(TEST_HDRS) | $(BUILD_DIR)
	$(CXX) $(TEST_CPPFLAGS) $(CXXFLAGS) $< $(PLATFORM_LIB) $(CORE_LIB) $(SYS_LIBS) -o $@

test-host: $(TEST_BINS)
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "==> $$t"; \
		if ./$$t; then :; else echo "FAILED: $$t"; fail=1; fi; \
	done; \
	if [ $$fail -ne 0 ]; then echo "test-host: one or more test binaries FAILED"; exit 1; fi; \
	echo "test-host: all $(words $(TEST_BINS)) test binaries passed"

ARM_MAKE_VARS = CXX=arm-linux-gnueabihf-g++ CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar \
		BUILD_DIR=build/arm-entrynav2 TARGET_OS=linux \
		CXXFLAGS="-std=gnu++0x -O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard $(COMMON_WARN)"

arm-core:
	$(MAKE) $(ARM_MAKE_VARS) core

arm-platform:
	$(MAKE) $(ARM_MAKE_VARS) EVO=1 platform

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf build

-include $(CORE_OBJS:.o=.d) $(PLATFORM_OBJS:.o=.d)
