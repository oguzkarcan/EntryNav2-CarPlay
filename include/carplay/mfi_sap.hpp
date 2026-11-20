#ifndef CARPLAY_MFI_SAP_HPP
#define CARPLAY_MFI_SAP_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/MfiSapAuthSetup.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// CarPlay AirPlay /auth-setup MFiSAP responder (accessory side).
//
// Request wire format:
//   [1-byte version = 0x01][32-byte controller X25519 public key]
// Response wire format:
//   [32-byte accessory ephemeral X25519 public key]
//   [4-byte BE certificate length][MFi X.509 DER certificate]
//   [4-byte BE encrypted signature length][AES-128-CTR(signature)]
//
// Session key/IV derivation:
//   aes_key = SHA-1("AES-KEY" || shared_secret)[0..16)
//   aes_iv  = SHA-1("AES-IV"  || shared_secret)[0..16)
//
// Coprocessor digest selection:
//   protocolMajor == 2 (CP 2.0C): SHA-1(accessory_pk || peer_pk)
//   protocolMajor != 2 (CP 3.0):  SHA-256(accessory_pk || peer_pk)

#include "carplay/airplay_session.hpp"
#include "carplay/pairing.hpp"

#include <stdint.h>
#include <vector>

namespace carplay {
namespace mfi_sap {

/// Executes the accessory side of AirPlay /auth-setup using `auth` and `rng`.
/// Returns true on success with the binary response in `response_out`.
/// Returns false on malformed requests, zero X25519 shared secret, or AuthProvider failures.
bool handleAuthSetup(const std::vector<uint8_t>& request_body,
                     session::AuthProvider& auth,
                     pairing::RandomSource& rng,
                     std::vector<uint8_t>& response_out);

}  // namespace mfi_sap
}  // namespace carplay

#endif  // CARPLAY_MFI_SAP_HPP
