#ifndef CARPLAY_AUTH_PROVIDER_HPP
#define CARPLAY_AUTH_PROVIDER_HPP

// Derived in part from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/mfi/Iap2MfiAuthenticationClient.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// Transport-agnostic MFi / authentication provider interface for iAP2 sessions.
//
// Phase 5 provides the real hardware MFi coprocessor or external BAA signer
// implementation; core iAP2 session logic and host tests program against this
// synchronous interface.

#include <stddef.h>
#include <stdint.h>

#include <vector>

namespace carplay {
namespace iap2 {

// MFi authentication bounds (verified: DiPlay Iap2MfiAuthenticationClient.kt:110-111).
static const size_t kMaxChallengeBytes = 128U;
static const size_t kMaxCertificateBytes = 65525U;

class AuthProvider {
public:
    virtual ~AuthProvider() {}

    /// Retrieves the accessory's DER-encoded X.509 MFi authentication certificate.
    /// Returns true on success with non-empty `certificate_out` (<= kMaxCertificateBytes).
    virtual bool getCertificate(std::vector<uint8_t>& certificate_out) = 0;

    /// Signs the device-supplied challenge bytes using the accessory's MFi key/coprocessor.
    /// Returns true on success with non-empty `signature_out` (challenge_len in 1..kMaxChallengeBytes).
    virtual bool signChallenge(const uint8_t* challenge,
                               size_t challenge_len,
                               std::vector<uint8_t>& signature_out) = 0;
};

}  // namespace iap2
}  // namespace carplay

#endif  // CARPLAY_AUTH_PROVIDER_HPP
