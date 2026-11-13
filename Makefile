# EntryNav2-CarPlay Makefile
# Designed for both Windows/Linux host testing (-std=gnu++0x) and HU_ENTRYNAV2 ARMv7 cross-builds.

CXX ?= g++
CC  ?= gcc
AR  ?= ar

COMMON_WARN := -Wall -Wextra -Werror
CXXFLAGS ?= -std=gnu++0x -O2 $(COMMON_WARN)
CFLAGS   ?= -std=c99 -O2 -Wall -Wextra
CPPFLAGS := -Iinclude -Ithird_party/monocypher

BUILD_DIR ?= build/host
BIN_EXT   ?=

CORE_CPP_SRCS := \
	src/core/airplay_crypto.cpp \
	src/core/tlv8_codec.cpp \
	src/core/bplist_codec.cpp \
	src/core/iap2_wire.cpp \
	src/core/airplay_hid.cpp \
	src/core/screen_stream.cpp

MONO_C_SRCS := \
	third_party/monocypher/monocypher.c \
	third_party/monocypher/monocypher-ed25519.c

CORE_OBJS := \
	$(patsubst src/core/%.cpp,$(BUILD_DIR)/core_%.o,$(CORE_CPP_SRCS)) \
	$(patsubst third_party/monocypher/%.c,$(BUILD_DIR)/mono_%.o,$(MONO_C_SRCS))

TEST_BIN := $(BUILD_DIR)/test_phase1$(BIN_EXT)
CORE_LIB := $(BUILD_DIR)/libcarplay_core.a

.PHONY: all core test-host clean arm-core

all: test-host

core: $(CORE_LIB)

$(CORE_LIB): $(CORE_OBJS)
	$(AR) rcs $@ $^

$(BUILD_DIR)/core_%.o: src/core/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/mono_%.o: third_party/monocypher/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TEST_BIN): tests/test_phase1.cpp $(CORE_LIB) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/test_phase1.cpp $(CORE_LIB) -o $@

test-host: $(TEST_BIN)
	./$(TEST_BIN)

arm-core:
	$(MAKE) CXX=arm-linux-gnueabihf-g++ CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar \
		BUILD_DIR=build/arm-entrynav2 \
		CXXFLAGS="-std=gnu++0x -O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard $(COMMON_WARN)" \
		core

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf build
