# EntryNav2-CarPlay Makefile
# Designed for both Windows/Linux host testing (-std=gnu++0x) and HU_ENTRYNAV2 ARMv7 cross-builds.
#
# Sources and tests are auto-discovered:
#   * every src/core/*.cpp is compiled into libcarplay_core.a
#   * every tests/test_*.cpp becomes its own binary $(BUILD_DIR)/test_<name>$(BIN_EXT)
# `make test-host` builds and runs all test binaries and fails if any one fails.

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

CORE_CPP_SRCS := $(sort $(wildcard src/core/*.cpp))

MONO_C_SRCS := \
	third_party/monocypher/monocypher.c \
	third_party/monocypher/monocypher-ed25519.c

CORE_OBJS := \
	$(patsubst src/core/%.cpp,$(BUILD_DIR)/core_%.o,$(CORE_CPP_SRCS)) \
	$(patsubst third_party/monocypher/%.c,$(BUILD_DIR)/mono_%.o,$(MONO_C_SRCS))

CORE_LIB := $(BUILD_DIR)/libcarplay_core.a

PUBLIC_HDRS := $(wildcard include/carplay/*.hpp)
TEST_HDRS   := $(wildcard tests/*.hpp)

TEST_SRCS := $(sort $(wildcard tests/test_*.cpp))
TEST_BINS := $(patsubst tests/%.cpp,$(BUILD_DIR)/%$(BIN_EXT),$(TEST_SRCS))

.PHONY: all core tests test-host clean arm-core

all: test-host

core: $(CORE_LIB)

tests: $(TEST_BINS)

$(CORE_LIB): $(CORE_OBJS)
	$(AR) rcs $@ $^

$(BUILD_DIR)/core_%.o: src/core/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/mono_%.o: third_party/monocypher/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%$(BIN_EXT): tests/test_%.cpp $(CORE_LIB) $(PUBLIC_HDRS) $(TEST_HDRS) | $(BUILD_DIR)
	$(CXX) $(TEST_CPPFLAGS) $(CXXFLAGS) $< $(CORE_LIB) -o $@

test-host: $(TEST_BINS)
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "==> $$t"; \
		if ./$$t; then :; else echo "FAILED: $$t"; fail=1; fi; \
	done; \
	if [ $$fail -ne 0 ]; then echo "test-host: one or more test binaries FAILED"; exit 1; fi; \
	echo "test-host: all $(words $(TEST_BINS)) test binaries passed"

arm-core:
	$(MAKE) CXX=arm-linux-gnueabihf-g++ CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar \
		BUILD_DIR=build/arm-entrynav2 \
		CXXFLAGS="-std=gnu++0x -O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard $(COMMON_WARN)" \
		core

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf build

-include $(CORE_OBJS:.o=.d)
