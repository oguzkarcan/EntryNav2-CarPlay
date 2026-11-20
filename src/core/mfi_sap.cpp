// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/MfiSapAuthSetup.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/mfi_sap.hpp"

#include "carplay/airplay_crypto.hpp"

#include <cstring>

namespace carplay {
namespace mfi_sap {

namespace {

const uint8_t kMfiSapVersion = 0x01U;

void appendBe32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xffU));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xffU));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xffU));
    out.push_back(static_cast<uint8_t>(value & 0xffU));
}

void deriveAesKeyOrIv(const char* label,
                      size_t label_len,
                      const uint8_t shared[crypto::kKeyBytes],
                      uint8_t out16[crypto::kAes128KeyBytes]) {
    uint8_t input[64];
    std::memcpy(input, label, label_len);
    std::memcpy(input + label_len, shared, crypto::kKeyBytes);

    uint8_t digest[crypto::kSha1Bytes];
    crypto::sha1(input, label_len + crypto::kKeyBytes, digest);
    std::memcpy(out16, digest, crypto::kAes128KeyBytes);

    crypto::wipe(input, sizeof(input));
    crypto::wipe(digest, sizeof(digest));
}

}  // namespace

bool handleAuthSetup(const std::vector<uint8_t>& request_body,
                     session::AuthProvider& auth,
                     pairing::RandomSource& rng,
                     std::vector<uint8_t>& response_out) {
    response_out.clear();

    if (request_body.size() != 1U + crypto::kKeyBytes || request_body[0] != kMfiSapVersion) {
        return false;
    }

    const uint8_t* peer_pk = &request_body[1];

    uint8_t secret[crypto::kKeyBytes];
    rng.fill(secret, sizeof(secret));
    crypto::X25519KeyPair pair;
    crypto::x25519FromSecret(secret, pair);
    crypto::wipe(secret, sizeof(secret));

    uint8_t shared[crypto::kKeyBytes];
    if (!crypto::x25519SharedSecret(pair.secret_key, peer_pk, shared)) {
        return false;
    }

    uint8_t aes_key[crypto::kAes128KeyBytes];
    uint8_t aes_iv[crypto::kAesBlockBytes];
    deriveAesKeyOrIv("AES-KEY", 7U, shared, aes_key);
    deriveAesKeyOrIv("AES-IV", 6U, shared, aes_iv);
    crypto::wipe(shared, sizeof(shared));

    std::vector<uint8_t> certificate;
    if (!auth.getCertificate(certificate) || certificate.empty()) {
        crypto::wipe(aes_key, sizeof(aes_key));
        crypto::wipe(aes_iv, sizeof(aes_iv));
        return false;
    }

    uint8_t pk_pair[crypto::kKeyBytes * 2];
    std::memcpy(pk_pair, pair.public_key, crypto::kKeyBytes);
    std::memcpy(pk_pair + crypto::kKeyBytes, peer_pk, crypto::kKeyBytes);

    std::vector<uint8_t> signature;
    bool signed_ok = false;
    if (auth.protocolMajor() == 2) {
        uint8_t digest[crypto::kSha1Bytes];
        crypto::sha1(pk_pair, sizeof(pk_pair), digest);
        signed_ok = auth.signChallenge(digest, sizeof(digest), signature);
        crypto::wipe(digest, sizeof(digest));
    } else {
        uint8_t digest[crypto::kSha256Bytes];
        crypto::sha256(pk_pair, sizeof(pk_pair), digest);
        signed_ok = auth.signChallenge(digest, sizeof(digest), signature);
        crypto::wipe(digest, sizeof(digest));
    }

    if (!signed_ok || signature.empty()) {
        crypto::wipe(aes_key, sizeof(aes_key));
        crypto::wipe(aes_iv, sizeof(aes_iv));
        return false;
    }

    std::vector<uint8_t> encrypted_signature(signature.size(), 0);
    const bool enc_ok = crypto::aes128Ctr(
        aes_key, aes_iv, &signature[0], signature.size(), &encrypted_signature[0]);
    crypto::wipe(aes_key, sizeof(aes_key));
    crypto::wipe(aes_iv, sizeof(aes_iv));
    crypto::wipe(&signature[0], signature.size());
    if (!enc_ok) {
        return false;
    }

    response_out.reserve(crypto::kKeyBytes + 4U + certificate.size() + 4U + encrypted_signature.size());
    response_out.insert(response_out.end(), pair.public_key, pair.public_key + crypto::kKeyBytes);
    appendBe32(response_out, static_cast<uint32_t>(certificate.size()));
    response_out.insert(response_out.end(), certificate.begin(), certificate.end());
    appendBe32(response_out, static_cast<uint32_t>(encrypted_signature.size()));
    response_out.insert(response_out.end(), encrypted_signature.begin(), encrypted_signature.end());
    return true;
}

}  // namespace mfi_sap
}  // namespace carplay
