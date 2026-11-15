#ifndef CARPLAY_PLATFORM_SERVICE_CONTRACT_HPP
#define CARPLAY_PLATFORM_SERVICE_CONTRACT_HPP

// Shared filesystem layout and IPC contract between the iDrive HMI plugin (libEntryCarPlay.so),
// the service supervisor, and the CarPlay daemon (carplayd) on BMW HU_ENTRYNAV2.
//
// Target partition layout on HU_ENTRYNAV2:
//   * /opt/carplay/carplayd                        (system partition, executable)
//   * /opt/hmi/data/ro/Plugins/EntryCarPlay/       (RHMI plugin .so, .manifest, .xml, text/image zips)
//   * /var/local/data/CarPlay/                     (persistent rw data partition; mounted noexec!)
//   * /tmp/                                        (tmpfs runtime state, sockets, logs)

#include <stdint.h>

namespace carplay {
namespace platform {
namespace contract {

// ---- System partition binaries & plugin directory (/opt) ----
static const char* const kSupervisor = "/opt/carplay/carplay-supervisor";
static const char* const kService = "/opt/carplay/carplayd";
static const char* const kPluginDir = "/opt/hmi/data/ro/Plugins/EntryCarPlay";
static const char* const kPluginLibrary = "/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay";
static const char* const kPluginManifest = "/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.manifest";
static const char* const kPluginXml = "/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.xml";

// ---- Persistent data directory (/var/local/data/CarPlay, survives reboot, mounted noexec) ----
static const char* const kDataDir = "/var/local/data/CarPlay";
static const char* const kIdentityFile = "/var/local/data/CarPlay/accessory_ltpk.key";
static const char* const kPairingsFile = "/var/local/data/CarPlay/controller_pairings.tsv";
static const char* const kAutostart = "/var/local/data/CarPlay/autostart";
static const char* const kEntryDirect = "/var/local/data/CarPlay/entry-direct";
static const char* const kMaintenance = "/var/local/data/CarPlay/maintenance";
static const char* const kUsb = "/var/local/data/CarPlay/usb";
static const char* const kVehicle = "/var/local/data/CarPlay/vehicle";
static const char* const kAppLog = "/var/local/data/CarPlay/app.log";
static const char* const kAppLogOld = "/var/local/data/CarPlay/app.old.log";
static const char* const kAppDisable = "/var/local/data/CarPlay/app.disable";
static const char* const kAppGuard = "/var/local/data/CarPlay/app-guard";
static const char* const kBootGuard = "/var/local/data/CarPlay/bootguard";

// ---- Runtime files in /tmp (tmpfs, cleared across reboot) ----
static const char* const kServiceDir = "/tmp/entry-carplay-service";
static const char* const kServiceStop = "/tmp/entry-carplay-service/STOP";
static const char* const kServiceLog = "/tmp/entry-carplay-service.log";
static const char* const kStateFile = "/tmp/entry-carplayd-state";
static const char* const kAppKeyFile = "/tmp/entry-carplayd-appkey";
static const char* const kDayNightFile = "/tmp/entry-carplayd-daynight";
static const char* const kWirelessLock = "/tmp/entry-carplayd-wireless.lock";
static const char* const kMediaRecallFile = "/tmp/entry-carplayd-media-recall";

// ---- Abstract Unix domain datagram socket name (\0entry-carplayd-control) ----
static const char* const kControlName = "entry-carplayd-control";

}  // namespace contract
}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_SERVICE_CONTRACT_HPP
