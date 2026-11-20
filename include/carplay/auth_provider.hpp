#ifndef CARPLAY_AUTH_PROVIDER_HPP
#define CARPLAY_AUTH_PROVIDER_HPP

// Derived in part from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/mfi/Iap2MfiAuthenticationClient.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// Transport-agnostic MFi / authentication provider interface for iAP2 sessions.
//
// Phase 5 provides I2cMfiAuthProvider for hardware MFi coprocessors (CP 2.0C / 3.0)
// using both synchronous and Reactor-timer asynchronous hooks.

#include <stddef.h>
#include <stdint.h>

#include <vector>

namespace carplay {
namespace iap2 {

// MFi authentication bounds (verified: DiPlay Iap2MfiAuthenticationClient.kt:110-111).
static const size_t kMaxChallengeBytes = 128U;
static const size_t kMaxCertificateBytes = 65525U;

/// Completion callback for asynchronous MFi AuthProvider operations on the Reactor thread.
class AuthCallback {
public:
    virtual ~AuthCallback() {}

    virtual void onCertificateComplete(uint64_t op_id,
                                       bool ok,
                                       const std::vector<uint8_t>& certificate) = 0;

    virtual void onSignatureComplete(uint64_t op_id,
                                     bool ok,
                                     const std::vector<uint8_t>& signature) = 0;
};

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

    /// Coprocessor protocol major version (2 = CP 2.0C, 3 = CP 3.0).
    virtual int protocolMajor() const {
        return 3;
    }

    /// Returns true when the provider executes multi-step I/O asynchronously via Reactor timers
    /// (`beginGetCertificate` / `beginSignChallenge`) to avoid blocking the Reactor thread.
    virtual bool isAsync() const {
        return false;
    }

    /// Starts an asynchronous certificate read.
    /// Returns op_id != 0 if completion will arrive asynchronously via `callback`;
    /// returns 0 if `callback.onCertificateComplete(0, ...)` was already invoked inline.
    virtual uint64_t beginGetCertificate(AuthCallback& callback) {
        std::vector<uint8_t> cert;
        const bool ok = getCertificate(cert);
        callback.onCertificateComplete(0ULL, ok, cert);
        return 0ULL;
    }

    /// Starts an asynchronous challenge signature.
    /// Returns op_id != 0 if completion will arrive asynchronously via `callback`;
    /// returns 0 if `callback.onSignatureComplete(0, ...)` was already invoked inline.
    virtual uint64_t beginSignChallenge(const uint8_t* challenge,
                                          size_t challenge_len,
                                          AuthCallback& callback) {
        std::vector<uint8_t> sig;
        const bool ok = signChallenge(challenge, challenge_len, sig);
        callback.onSignatureComplete(0ULL, ok, sig);
        return 0ULL;
    }

    /// Cancels an in-flight asynchronous operation returned by `beginGetCertificate` or
    /// `beginSignChallenge`. Safe to call with 0 or an already-completed op_id.
    virtual void cancelAuth(uint64_t /*op_id*/) {}
};

}  // namespace iap2
}  // namespace carplay

#endif  // CARPLAY_AUTH_PROVIDER_HPP
