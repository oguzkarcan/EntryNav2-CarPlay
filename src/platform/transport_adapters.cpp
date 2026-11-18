#include "carplay/platform/transport_adapters.hpp"

#include "carplay/iap2_wire.hpp"

namespace carplay {
namespace platform {

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

bool hasControlChars(const std::string& s) {
    for (size_t i = 0U; i < s.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x20U || c == 0x7fU) {
            return true;
        }
    }
    return false;
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// BtSessionAdapter
// ------------------------------------------------------------------------------------------------

BtSessionAdapter::BtSessionAdapter(BtTransport* transport,
                                   iap2::Session* session,
                                   BtTransportListener* downstream)
    : transport_(transport), session_(session), downstream_(downstream) {}

bool BtSessionAdapter::sendBytes(const uint8_t* data, size_t len) {
    if (transport_ == NULL || data == NULL || len == 0U) {
        return false;
    }
    return transport_->sendBytes(data, len);
}

void BtSessionAdapter::onBtTransportConnected(const BtAddr& peer) {
    if (downstream_ != NULL) {
        downstream_->onBtTransportConnected(peer);
    }
    if (session_ != NULL) {
        session_->start();
    }
}

void BtSessionAdapter::onBtTransportData(const uint8_t* data, size_t len) {
    if (session_ != NULL && data != NULL && len > 0U) {
        session_->feed(data, len);
    }
    if (downstream_ != NULL) {
        downstream_->onBtTransportData(data, len);
    }
}

void BtSessionAdapter::onBtTransportDisconnected(const std::string& reason) {
    if (session_ != NULL && session_->state() != iap2::kSessionIdle) {
        session_->reset(false);
    }
    if (downstream_ != NULL) {
        downstream_->onBtTransportDisconnected(reason);
    }
}

// ------------------------------------------------------------------------------------------------
// UsbBridgeSessionAdapter
// ------------------------------------------------------------------------------------------------

UsbBridgeSessionAdapter::UsbBridgeSessionAdapter(UsbCarPlayBridge* bridge,
                                                 iap2::Session* session,
                                                 UsbCarPlayBridgeListener* downstream)
    : bridge_(bridge), session_(session), downstream_(downstream) {}

bool UsbBridgeSessionAdapter::sendBytes(const uint8_t* data, size_t len) {
    if (bridge_ == NULL || data == NULL || len == 0U) {
        return false;
    }
    return bridge_->writeIap2(data, len);
}

void UsbBridgeSessionAdapter::onBridgeStateChanged(BridgeState state) {
    if (downstream_ != NULL) {
        downstream_->onBridgeStateChanged(state);
    }
}

void UsbBridgeSessionAdapter::onIap2Ready(const usb::Iap2InterfaceSelection& iap2) {
    if (downstream_ != NULL) {
        downstream_->onIap2Ready(iap2);
    }
    if (session_ != NULL) {
        session_->start();
    }
}

void UsbBridgeSessionAdapter::onIap2Data(const uint8_t* data, size_t len) {
    if (session_ != NULL && data != NULL && len > 0U) {
        session_->feed(data, len);
    }
    if (downstream_ != NULL) {
        downstream_->onIap2Data(data, len);
    }
}

void UsbBridgeSessionAdapter::onNcmReady(const std::string& tap_ifname,
                                         uint32_t tap_ifindex,
                                         const uint8_t tap_mac[6]) {
    if (downstream_ != NULL) {
        downstream_->onNcmReady(tap_ifname, tap_ifindex, tap_mac);
    }
}

void UsbBridgeSessionAdapter::onDeviceRemoved() {
    if (session_ != NULL && session_->state() != iap2::kSessionIdle) {
        session_->reset(false);
    }
    if (downstream_ != NULL) {
        downstream_->onDeviceRemoved();
    }
}

void UsbBridgeSessionAdapter::onBridgeError(const std::string& reason) {
    if (downstream_ != NULL) {
        downstream_->onBridgeError(reason);
    }
}

// ------------------------------------------------------------------------------------------------
// Wi-Fi 0x5703 Credential Conversion & WifiApCredentialsAdapter
// ------------------------------------------------------------------------------------------------

bool toIap2WiFiConfiguration(const WifiCredentials& creds,
                             iap2::WiFiConfiguration& out,
                             std::string* error_out) {
    if (creds.ssid.empty() || creds.ssid.size() > 32U || hasControlChars(creds.ssid)) {
        setError(error_out, "invalid Wi-Fi SSID for iAP2 0x5703");
        return false;
    }
    if (creds.channel == 0U) {
        setError(error_out, "invalid Wi-Fi channel for iAP2 0x5703");
        return false;
    }
    if (creds.security_type != iap2::kWirelessSecurityNone) {
        if (creds.passphrase.size() < 8U || creds.passphrase.size() > 63U ||
            hasControlChars(creds.passphrase)) {
            setError(error_out, "invalid Wi-Fi passphrase for secured iAP2 0x5703");
            return false;
        }
    }

    iap2::WiFiConfiguration cfg;
    cfg.ssid = creds.ssid;
    cfg.passphrase = creds.passphrase;
    cfg.channel = creds.channel;
    cfg.security_type = creds.security_type;
    cfg.bssid = creds.bssidVector();
    out = cfg;
    return true;
}

bool populateIap2WiFiConfiguration(const WifiAp& ap,
                                   iap2::WiFiConfiguration& out,
                                   std::string* error_out) {
    if (ap.state() != kWifiApRunning) {
        setError(error_out, "WifiAp is not running");
        return false;
    }
    return toIap2WiFiConfiguration(ap.credentials(), out, error_out);
}

WifiApCredentialsAdapter::WifiApCredentialsAdapter(const WifiAp* ap, WifiApListener* downstream)
    : ap_(ap), downstream_(downstream), has_credentials_(false) {}

void WifiApCredentialsAdapter::clearCredentials() {
    has_credentials_ = false;
    credentials_ = WifiCredentials();
}

bool WifiApCredentialsAdapter::hasCredentials() const {
    if (has_credentials_) {
        return true;
    }
    return ap_ != NULL && ap_->state() == kWifiApRunning;
}

bool WifiApCredentialsAdapter::provideWiFiConfiguration(iap2::WiFiConfiguration& out,
                                                        std::string* error_out) const {
    if (has_credentials_) {
        return toIap2WiFiConfiguration(credentials_, out, error_out);
    }
    if (ap_ != NULL) {
        return populateIap2WiFiConfiguration(*ap_, out, error_out);
    }
    setError(error_out, "no Wi-Fi AP credentials available");
    return false;
}

void WifiApCredentialsAdapter::onWifiApStarted(const WifiCredentials& creds) {
    credentials_ = creds;
    has_credentials_ = true;
    if (downstream_ != NULL) {
        downstream_->onWifiApStarted(creds);
    }
}

void WifiApCredentialsAdapter::onWifiApStopped() {
    clearCredentials();
    if (downstream_ != NULL) {
        downstream_->onWifiApStopped();
    }
}

void WifiApCredentialsAdapter::onWifiApRestarting(int attempt, const std::string& reason) {
    clearCredentials();
    if (downstream_ != NULL) {
        downstream_->onWifiApRestarting(attempt, reason);
    }
}

void WifiApCredentialsAdapter::onWifiApFailed(const std::string& reason) {
    clearCredentials();
    if (downstream_ != NULL) {
        downstream_->onWifiApFailed(reason);
    }
}

void WifiApCredentialsAdapter::onStationConnected(const std::string& mac) {
    if (downstream_ != NULL) {
        downstream_->onStationConnected(mac);
    }
}

void WifiApCredentialsAdapter::onStationDisconnected(const std::string& mac) {
    if (downstream_ != NULL) {
        downstream_->onStationDisconnected(mac);
    }
}

}  // namespace platform
}  // namespace carplay
