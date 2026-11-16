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
PYTHON3 ?= python3

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
PIC_FLAG :=
else
SYS_LIBS ?= -lpthread -lrt -ldl
PIC_FLAG := -fPIC
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

DAEMON_BIN := $(BUILD_DIR)/carplayd$(BIN_EXT)
STAGE_DIR  ?= $(BUILD_DIR)/install-root

ifeq ($(TARGET_OS),linux)
HMI_PLUGIN_SO := $(BUILD_DIR)/libEntryCarPlay.so
else
HMI_PLUGIN_SO :=
endif

HMI_TEXTS_ZIP  := $(BUILD_DIR)/EntryCarPlay_ALL_Texts.zip
HMI_IMAGES_ZIP := $(BUILD_DIR)/EntryCarPlay_ALL_Images.zip

PUBLIC_HDRS := $(wildcard include/carplay/*.hpp) $(wildcard include/carplay/platform/*.hpp)
TEST_HDRS   := $(wildcard tests/*.hpp)

TEST_SRCS := $(sort $(wildcard tests/test_*.cpp))
TEST_BINS := $(patsubst tests/%.cpp,$(BUILD_DIR)/%$(BIN_EXT),$(TEST_SRCS))

.PHONY: all core platform daemon hmiapp hmiapp-res install-layout tests test-host clean arm-core arm-platform arm-daemon arm-hmiapp

all: test-host

core: $(CORE_LIB)

platform: $(PLATFORM_LIB) $(CORE_LIB)

daemon: $(DAEMON_BIN)

hmiapp: $(HMI_PLUGIN_SO)

hmiapp-res: $(HMI_TEXTS_ZIP) $(HMI_IMAGES_ZIP)

tests: $(TEST_BINS) $(DAEMON_BIN) $(HMI_PLUGIN_SO)

$(CORE_LIB): $(CORE_OBJS)
	$(AR) rcs $@ $^

$(PLATFORM_LIB): $(PLATFORM_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD_DIR)/core_%.o: src/core/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(PIC_FLAG) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/plat_%.o: src/platform/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(PIC_FLAG) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/evo_%.o: src/platform/evo/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(PIC_FLAG) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/mono_%.o: third_party/monocypher/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PIC_FLAG) $(DEPFLAGS) -c $< -o $@

$(DAEMON_BIN): src/daemon/main.cpp $(PLATFORM_LIB) $(CORE_LIB) $(PUBLIC_HDRS) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< $(PLATFORM_LIB) $(CORE_LIB) $(SYS_LIBS) -o $@

# The plugin is loaded into HmiMain3D: export only the entry points that carry an
# explicit default-visibility attribute, never the statically linked core/platform/
# monocypher symbols (they could interpose with the host or another plugin).
$(BUILD_DIR)/libEntryCarPlay.so: src/hmi/entry_carplay_app.cpp $(PLATFORM_LIB) $(CORE_LIB) $(PUBLIC_HDRS) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fPIC -fvisibility=hidden -fvisibility-inlines-hidden -shared \
		-Wl,-soname,libEntryCarPlay.so -Wl,--exclude-libs,ALL \
		$< $(PLATFORM_LIB) $(CORE_LIB) $(SYS_LIBS) -o $@

$(HMI_TEXTS_ZIP): hmiapp/make_db.py hmiapp/EntryCarPlay.xml hmiapp/EntryCarPlay.manifest | $(BUILD_DIR)
	$(PYTHON3) hmiapp/make_db.py --xml hmiapp/EntryCarPlay.xml --texts $@

$(HMI_IMAGES_ZIP): hmiapp/make_db.py hmiapp/EntryCarPlay.xml hmiapp/EntryCarPlay.manifest | $(BUILD_DIR)
	$(PYTHON3) hmiapp/make_db.py --xml hmiapp/EntryCarPlay.xml --images $@

install-layout: $(DAEMON_BIN) $(HMI_PLUGIN_SO) hmiapp/EntryCarPlay.manifest hmiapp/EntryCarPlay.xml $(HMI_TEXTS_ZIP) $(HMI_IMAGES_ZIP)
	mkdir -p $(STAGE_DIR)/opt/carplay
	mkdir -p $(STAGE_DIR)/opt/hmi/data/ro/Plugins/EntryCarPlay
	mkdir -p $(STAGE_DIR)/var/local/data/CarPlay
	cp $(DAEMON_BIN) $(STAGE_DIR)/opt/carplay/carplayd
	chmod 0755 $(STAGE_DIR)/opt/carplay/carplayd
	if [ -n "$(HMI_PLUGIN_SO)" ] && [ -f "$(HMI_PLUGIN_SO)" ]; then \
		cp $(HMI_PLUGIN_SO) $(STAGE_DIR)/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay; \
		cp $(HMI_PLUGIN_SO) $(STAGE_DIR)/opt/hmi/data/ro/Plugins/EntryCarPlay/libEntryCarPlay.so; \
	fi
	cp hmiapp/EntryCarPlay.manifest $(STAGE_DIR)/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.manifest
	cp hmiapp/EntryCarPlay.xml $(STAGE_DIR)/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.xml
	cp $(HMI_TEXTS_ZIP) $(STAGE_DIR)/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay_ALL_Texts.zip
	cp $(HMI_IMAGES_ZIP) $(STAGE_DIR)/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay_ALL_Images.zip

$(BUILD_DIR)/test_%$(BIN_EXT): tests/test_%.cpp $(PLATFORM_LIB) $(CORE_LIB) $(PUBLIC_HDRS) $(TEST_HDRS) | $(BUILD_DIR)
	$(CXX) $(TEST_CPPFLAGS) $(CXXFLAGS) $< $(PLATFORM_LIB) $(CORE_LIB) $(SYS_LIBS) -o $@

test-host: $(TEST_BINS) $(DAEMON_BIN) $(HMI_PLUGIN_SO)
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

arm-daemon:
	$(MAKE) $(ARM_MAKE_VARS) EVO=1 daemon

arm-hmiapp:
	$(MAKE) $(ARM_MAKE_VARS) EVO=1 hmiapp

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf build

-include $(CORE_OBJS:.o=.d) $(PLATFORM_OBJS:.o=.d)
