#include "carplay/pairing.hpp"

#include <string.h>

// Error-state table (request situation -> reply {0x06 state, 0x07 0x02}), mirroring the
// DiPlay reference. "throws" = the reference reaches its catch block and echoes the request state.
//
//   both   body not decodable as TLV8 (hardening; reference decodes leniently)  -> state 0
//   both   state item missing / empty                                         -> state 0
//   both   unknown state value s                                              -> state s
//   setup  M1: RNG failure / SRP start failure (throws)                       -> state 1
//   setup  M3: no M1 pending, A or proof missing, SRP proof wrong             -> state 4
//   setup  M5: no successful M4 pending, encrypted data missing               -> state 6
//   setup  M5: AEAD open fails (throws: AEADBadTagException)                  -> state 5
//   setup  M5: sub-TLV missing id/LTPK/signature, bad lengths, bad signature,
//              store failure                                                  -> state 6
//   verify M1: public key missing                                             -> state 2
//   verify M1: public key length != 32, all-zero shared, RNG failure (throws) -> state 1
//   verify M3: no M1 pending, encrypted data missing                          -> state 4
//   verify M3: AEAD open fails (throws)                                       -> state 3
//   verify M3: sub-TLV missing id/signature, bad lengths, unknown controller,
//              bad signature                                                  -> state 4

namespace carplay {
namespace pairing {

const char* const kSetupUsername = "Pair-Setup";
const char* const kSetupCode = "3939";

namespace {

const char* const kPsEncryptSalt = "Pair-Setup-Encrypt-Salt";
const char* const kPsEncryptInfo = "Pair-Setup-Encrypt-Info";
const char* const kPsControllerSignSalt = "Pair-Setup-Controller-Sign-Salt";
const char* const kPsControllerSignInfo = "Pair-Setup-Controller-Sign-Info";
const char* const kPsAccessorySignSalt = "Pair-Setup-Accessory-Sign-Salt";
const char* const kPsAccessorySignInfo = "Pair-Setup-Accessory-Sign-Info";
const char* const kPsMsg05 = "PS-Msg05";
const char* const kPsMsg06 = "PS-Msg06";

const char* const kPvEncryptSalt = "Pair-Verify-Encrypt-Salt";
const char* const kPvEncryptInfo = "Pair-Verify-Encrypt-Info";
const char* const kPvMsg02 = "PV-Msg02";
const char* const kPvMsg03 = "PV-Msg03";

const char* const kControlSalt = "Control-Salt";
const char* const kControlReadInfo = "Control-Read-Encryption-Key";
const char* const kControlWriteInfo = "Control-Write-Encryption-Key";
const char* const kEventsSalt = "Events-Salt";
const char* const kEventsReadInfo = "Events-Read-Encryption-Key";
const char* const kEventsWriteInfo = "Events-Write-Encryption-Key";

typedef std::vector<tlv8::Item> Items;

bool hkdf32(const uint8_t* ikm, size_t ikm_len, const char* salt, const char* info,
            uint8_t out[crypto::kKeyBytes]) {
    return crypto::hkdfSha512(ikm, ikm_len, reinterpret_cast<const uint8_t*>(salt), strlen(salt),
                              reinterpret_cast<const uint8_t*>(info), strlen(info), out,
                              crypto::kKeyBytes);
}

void append(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    if (data != NULL && len > 0) {
        out.insert(out.end(), data, data + len);
    }
}

void append(std::vector<uint8_t>& out, const std::string& s) {
    append(out, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void wipeVector(std::vector<uint8_t>& v) {
    if (!v.empty()) {
        crypto::wipe(&v[0], v.size());
    }
    v.clear();
}

void wipeItems(Items& items) {
    for (size_t i = 0; i < items.size(); ++i) {
        wipeVector(items[i].value);
    }
    items.clear();
}

const uint8_t* ptrOf(const std::vector<uint8_t>& v) {
    return v.empty() ? NULL : &v[0];
}

std::vector<uint8_t> errorReply(uint8_t state) {
    Items items;
    items.push_back(tlv8::Item::fromByte(tlv8::kTagState, state));
    items.push_back(tlv8::Item::fromByte(tlv8::kTagError, kErrorAuthentication));
    return tlv8::encode(items);
}

// Reference: tlv[TYPE_STATE]?.firstOrNull() -> first byte of the value, missing/empty -> 0.
uint8_t requestState(const Items& items) {
    const tlv8::Item* item = tlv8::findFirst(items, tlv8::kTagState);
    if (item == NULL || item->value.empty()) {
        return 0;
    }
    return item->value[0];
}

bool validControllerId(const tlv8::Item* id) {
    return id != NULL && !id->value.empty() && id->value.size() <= kMaxControllerIdBytes;
}

bool labelNonce(const char* label, uint8_t nonce[crypto::kNonceBytes]) {
    return crypto::makeLabelNonce(std::string(label), nonce);
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------------------------

bool Identity::initFromSeed(const uint8_t seed[crypto::kEd25519SeedBytes], const std::string& id) {
    clear();
    if (seed == NULL || id.empty() || id.size() > kMaxAccessoryIdBytes) {
        return false;
    }
    crypto::ed25519FromSeed(seed, keys);
    pairing_id = id;
    return true;
}

void Identity::clear() {
    crypto::wipe(keys.secret_key, sizeof(keys.secret_key));
    crypto::wipe(keys.public_key, sizeof(keys.public_key));
    pairing_id.clear();
}

std::string formatPairingId(const uint8_t random16[kPairingIdRandomBytes]) {
    static const char kDigits[] = "0123456789abcdef";
    uint8_t b[kPairingIdRandomBytes];
    memcpy(b, random16, sizeof(b));
    b[6] = static_cast<uint8_t>((b[6] & 0x0f) | 0x40);  // version 4
    b[8] = static_cast<uint8_t>((b[8] & 0x3f) | 0x80);  // RFC 4122 variant
    std::string out;
    out.reserve(36);
    for (size_t i = 0; i < sizeof(b); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out.push_back('-');
        }
        out.push_back(kDigits[(b[i] >> 4) & 0x0f]);
        out.push_back(kDigits[b[i] & 0x0f]);
    }
    crypto::wipe(b, sizeof(b));
    return out;
}

bool generateIdentity(RandomSource& rng, Identity& out) {
    out.clear();
    uint8_t seed[crypto::kEd25519SeedBytes];
    uint8_t uuid[kPairingIdRandomBytes];
    bool ok = rng.fill(seed, sizeof(seed)) && rng.fill(uuid, sizeof(uuid));
    if (ok) {
        ok = out.initFromSeed(seed, formatPairingId(uuid));
    }
    crypto::wipe(seed, sizeof(seed));
    crypto::wipe(uuid, sizeof(uuid));
    return ok;
}

// ---------------------------------------------------------------------------------------------
// InMemoryPairingStore
// ---------------------------------------------------------------------------------------------

bool InMemoryPairingStore::save(const std::string& id,
                                const uint8_t ltpk[crypto::kEd25519PublicKeyBytes]) {
    if (ltpk == NULL) {
        return false;
    }
    entries_[id] = std::vector<uint8_t>(ltpk, ltpk + crypto::kEd25519PublicKeyBytes);
    return true;
}

bool InMemoryPairingStore::get(const std::string& id,
                               uint8_t ltpk_out[crypto::kEd25519PublicKeyBytes]) const {
    if (ltpk_out == NULL) {
        return false;
    }
    std::map<std::string, std::vector<uint8_t> >::const_iterator it = entries_.find(id);
    if (it == entries_.end() || it->second.size() != crypto::kEd25519PublicKeyBytes) {
        return false;
    }
    memcpy(ltpk_out, &it->second[0], crypto::kEd25519PublicKeyBytes);
    return true;
}

void InMemoryPairingStore::clear() {
    entries_.clear();
}

// ---------------------------------------------------------------------------------------------
// Key derivation helpers
// ---------------------------------------------------------------------------------------------

bool deriveControlKeys(const uint8_t shared[crypto::kKeyBytes],
                       uint8_t read_key[crypto::kKeyBytes],
                       uint8_t write_key[crypto::kKeyBytes]) {
    if (shared == NULL || read_key == NULL || write_key == NULL) {
        return false;
    }
    // Deliberate swap (PairVerify.kt): the accessory reads what the controller writes.
    if (!hkdf32(shared, crypto::kKeyBytes, kControlSalt, kControlWriteInfo, read_key) ||
        !hkdf32(shared, crypto::kKeyBytes, kControlSalt, kControlReadInfo, write_key)) {
        crypto::wipe(read_key, crypto::kKeyBytes);
        crypto::wipe(write_key, crypto::kKeyBytes);
        return false;
    }
    return true;
}

bool deriveEventKeys(const uint8_t shared[crypto::kKeyBytes],
                     uint8_t read_key[crypto::kKeyBytes],
                     uint8_t write_key[crypto::kKeyBytes]) {
    if (shared == NULL || read_key == NULL || write_key == NULL) {
        return false;
    }
    // AirPlaySession.acceptEvent(): no swap.
    if (!hkdf32(shared, crypto::kKeyBytes, kEventsSalt, kEventsReadInfo, read_key) ||
        !hkdf32(shared, crypto::kKeyBytes, kEventsSalt, kEventsWriteInfo, write_key)) {
        crypto::wipe(read_key, crypto::kKeyBytes);
        crypto::wipe(write_key, crypto::kKeyBytes);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// PairSetup
// ---------------------------------------------------------------------------------------------

PairSetup::PairSetup(const Identity& identity, PairingStore& store, RandomSource& rng)
    : identity_(identity), store_(store), rng_(rng), stage_(kIdle), complete_(false) {
    crypto::wipe(session_key_, sizeof(session_key_));
}

PairSetup::~PairSetup() {
    reset();
}

void PairSetup::reset() {
    srp_.reset();
    crypto::wipe(session_key_, sizeof(session_key_));
    stage_ = kIdle;
    complete_ = false;
}

void PairSetup::fail(uint8_t state, std::vector<uint8_t>& response_out) {
    reset();
    response_out = errorReply(state);
}

void PairSetup::handle(const std::vector<uint8_t>& body, std::vector<uint8_t>& response_out) {
    handle(ptrOf(body), body.size(), response_out);
}

void PairSetup::handle(const uint8_t* body, size_t len, std::vector<uint8_t>& response_out) {
    response_out.clear();
    Items items;
    if (!tlv8::decode(body, len, items)) {
        fail(0, response_out);
        return;
    }
    const uint8_t state = requestState(items);
    switch (state) {
        case 1:
            onM1(response_out);
            break;
        case 3:
            onM3(items, response_out);
            break;
        case 5:
            onM5(items, response_out);
            break;
        default:
            fail(state, response_out);
            break;
    }
    wipeItems(items);
}

void PairSetup::onM1(std::vector<uint8_t>& response_out) {
    reset();
    // Reference order: salt first, then the private exponent b.
    uint8_t salt[srp::kSaltBytes];
    uint8_t b[srp::kPrivateKeyBytes];
    const bool ok = identity_.valid() && rng_.fill(salt, sizeof(salt)) && rng_.fill(b, sizeof(b)) &&
                    srp_.start(kSetupUsername, kSetupCode, salt, b);
    crypto::wipe(salt, sizeof(salt));
    crypto::wipe(b, sizeof(b));
    if (!ok) {
        fail(1, response_out);
        return;
    }
    Items reply;
    reply.push_back(tlv8::Item::fromByte(tlv8::kTagState, 2));
    reply.push_back(tlv8::Item(tlv8::kTagPublicKey, srp_.publicKey()));
    reply.push_back(tlv8::Item(tlv8::kTagSalt, srp_.salt()));
    response_out = tlv8::encode(reply);
    stage_ = kAwaitM3;
}

void PairSetup::onM3(const Items& items, std::vector<uint8_t>& response_out) {
    const tlv8::Item* a = tlv8::findFirst(items, tlv8::kTagPublicKey);
    const tlv8::Item* proof = tlv8::findFirst(items, tlv8::kTagProof);
    if (stage_ != kAwaitM3 || a == NULL || proof == NULL) {
        fail(4, response_out);
        return;
    }
    std::vector<uint8_t> k;
    std::vector<uint8_t> m2;
    const bool ok = srp_.verify(ptrOf(a->value), a->value.size(), ptrOf(proof->value),
                                proof->value.size(), k, m2);
    // Single attempt per M1: the SRP session is discarded whatever the outcome.
    srp_.reset();
    if (!ok || k.size() != srp::kSessionKeyBytes) {
        wipeVector(k);
        fail(4, response_out);
        return;
    }
    memcpy(session_key_, &k[0], sizeof(session_key_));
    wipeVector(k);
    Items reply;
    reply.push_back(tlv8::Item::fromByte(tlv8::kTagState, 4));
    reply.push_back(tlv8::Item(tlv8::kTagProof, m2));
    response_out = tlv8::encode(reply);
    stage_ = kAwaitM5;
}

void PairSetup::onM5(const Items& items, std::vector<uint8_t>& response_out) {
    const tlv8::Item* encrypted = tlv8::findFirst(items, tlv8::kTagEncryptedData);
    if (stage_ != kAwaitM5 || encrypted == NULL) {
        fail(6, response_out);
        return;
    }

    uint8_t key[crypto::kKeyBytes];
    uint8_t sign_key[crypto::kKeyBytes];
    uint8_t nonce[crypto::kNonceBytes];
    std::vector<uint8_t> plain;
    std::vector<uint8_t> sign_data;
    Items sub;
    uint8_t result_state = 0;  // 0 = success

    do {
        if (!hkdf32(session_key_, sizeof(session_key_), kPsEncryptSalt, kPsEncryptInfo, key) ||
            !labelNonce(kPsMsg05, nonce)) {
            result_state = 5;
            break;
        }
        if (!crypto::chacha20Poly1305Open(key, nonce, NULL, 0, ptrOf(encrypted->value),
                                          encrypted->value.size(), plain)) {
            result_state = 5;  // reference: chachaOpen throws -> err(request state)
            break;
        }
        result_state = 6;
        if (!tlv8::decode(ptrOf(plain), plain.size(), sub)) {
            break;
        }
        const tlv8::Item* id = tlv8::findFirst(sub, tlv8::kTagIdentifier);
        const tlv8::Item* ltpk = tlv8::findFirst(sub, tlv8::kTagPublicKey);
        const tlv8::Item* sig = tlv8::findFirst(sub, tlv8::kTagSignature);
        if (!validControllerId(id) || ltpk == NULL ||
            ltpk->value.size() != crypto::kEd25519PublicKeyBytes || sig == NULL ||
            sig->value.size() != crypto::kEd25519SignatureBytes) {
            break;
        }
        if (!hkdf32(session_key_, sizeof(session_key_), kPsControllerSignSalt,
                    kPsControllerSignInfo, sign_key)) {
            break;
        }
        append(sign_data, sign_key, sizeof(sign_key));
        append(sign_data, ptrOf(id->value), id->value.size());
        append(sign_data, ptrOf(ltpk->value), ltpk->value.size());
        if (!crypto::ed25519Verify(&ltpk->value[0], &sign_data[0], sign_data.size(),
                                   &sig->value[0])) {
            break;
        }
        const std::string controller_id(reinterpret_cast<const char*>(&id->value[0]),
                                        id->value.size());
        if (!store_.save(controller_id, &ltpk->value[0])) {
            break;
        }

        // M6: accessory proof.
        wipeVector(sign_data);
        if (!hkdf32(session_key_, sizeof(session_key_), kPsAccessorySignSalt, kPsAccessorySignInfo,
                    sign_key)) {
            break;
        }
        append(sign_data, sign_key, sizeof(sign_key));
        append(sign_data, identity_.pairing_id);
        append(sign_data, identity_.keys.public_key, sizeof(identity_.keys.public_key));
        uint8_t signature[crypto::kEd25519SignatureBytes];
        crypto::ed25519Sign(identity_.keys.secret_key, &sign_data[0], sign_data.size(), signature);

        Items sub_reply;
        sub_reply.push_back(tlv8::Item::fromString(tlv8::kTagIdentifier, identity_.pairing_id));
        sub_reply.push_back(tlv8::Item(tlv8::kTagPublicKey, identity_.keys.public_key,
                                       sizeof(identity_.keys.public_key)));
        sub_reply.push_back(tlv8::Item(tlv8::kTagSignature, signature, sizeof(signature)));
        std::vector<uint8_t> sub_bytes = tlv8::encode(sub_reply);
        std::vector<uint8_t> sealed;
        const bool sealed_ok = labelNonce(kPsMsg06, nonce) &&
                               crypto::chacha20Poly1305Seal(key, nonce, NULL, 0, ptrOf(sub_bytes),
                                                            sub_bytes.size(), sealed);
        wipeVector(sub_bytes);
        if (!sealed_ok) {
            break;
        }
        Items reply;
        reply.push_back(tlv8::Item::fromByte(tlv8::kTagState, 6));
        reply.push_back(tlv8::Item(tlv8::kTagEncryptedData, sealed));
        response_out = tlv8::encode(reply);
        result_state = 0;
    } while (false);

    crypto::wipe(key, sizeof(key));
    crypto::wipe(sign_key, sizeof(sign_key));
    wipeVector(plain);
    wipeVector(sign_data);
    wipeItems(sub);

    if (result_state != 0) {
        fail(result_state, response_out);
        return;
    }
    // Exchange finished: the session key is no longer needed.
    crypto::wipe(session_key_, sizeof(session_key_));
    stage_ = kIdle;
    complete_ = true;
}

// ---------------------------------------------------------------------------------------------
// PairVerify
// ---------------------------------------------------------------------------------------------

PairVerify::PairVerify(const Identity& identity, PairingStore& store, RandomSource& rng)
    : identity_(identity), store_(store), rng_(rng), stage_(kIdle) {
    reset();
}

PairVerify::~PairVerify() {
    reset();
}

void PairVerify::reset() {
    crypto::wipe(own_public_, sizeof(own_public_));
    crypto::wipe(peer_public_, sizeof(peer_public_));
    crypto::wipe(shared_, sizeof(shared_));
    crypto::wipe(encrypt_key_, sizeof(encrypt_key_));
    crypto::wipe(read_key_, sizeof(read_key_));
    crypto::wipe(write_key_, sizeof(write_key_));
    controller_id_.clear();
    stage_ = kIdle;
}

void PairVerify::fail(uint8_t state, std::vector<uint8_t>& response_out) {
    reset();
    response_out = errorReply(state);
}

bool PairVerify::sharedSecret(uint8_t out[crypto::kKeyBytes]) const {
    if (stage_ != kVerified || out == NULL) {
        return false;
    }
    memcpy(out, shared_, sizeof(shared_));
    return true;
}

bool PairVerify::controlKeys(uint8_t read_key[crypto::kKeyBytes],
                             uint8_t write_key[crypto::kKeyBytes]) const {
    if (stage_ != kVerified || read_key == NULL || write_key == NULL) {
        return false;
    }
    memcpy(read_key, read_key_, sizeof(read_key_));
    memcpy(write_key, write_key_, sizeof(write_key_));
    return true;
}

void PairVerify::handle(const std::vector<uint8_t>& body, std::vector<uint8_t>& response_out) {
    handle(ptrOf(body), body.size(), response_out);
}

void PairVerify::handle(const uint8_t* body, size_t len, std::vector<uint8_t>& response_out) {
    response_out.clear();
    Items items;
    if (!tlv8::decode(body, len, items)) {
        fail(0, response_out);
        return;
    }
    const uint8_t state = requestState(items);
    switch (state) {
        case 1:
            onM1(items, response_out);
            break;
        case 3:
            onM3(items, response_out);
            break;
        default:
            fail(state, response_out);
            break;
    }
    wipeItems(items);
}

void PairVerify::onM1(const Items& items, std::vector<uint8_t>& response_out) {
    reset();
    const tlv8::Item* peer = tlv8::findFirst(items, tlv8::kTagPublicKey);
    if (peer == NULL) {
        fail(2, response_out);
        return;
    }
    if (peer->value.size() != crypto::kKeyBytes || !identity_.valid()) {
        fail(1, response_out);  // reference: X25519PublicKeyParameters / agreement throws
        return;
    }
    memcpy(peer_public_, &peer->value[0], sizeof(peer_public_));

    uint8_t secret[crypto::kKeyBytes];
    bool ok = rng_.fill(secret, sizeof(secret));
    if (ok) {
        crypto::X25519KeyPair pair;
        crypto::x25519FromSecret(secret, pair);
        memcpy(own_public_, pair.public_key, sizeof(own_public_));
        // Rejects an all-zero (low-order) shared secret.
        ok = crypto::x25519SharedSecret(pair.secret_key, peer_public_, shared_);
    }
    crypto::wipe(secret, sizeof(secret));
    if (!ok || !hkdf32(shared_, sizeof(shared_), kPvEncryptSalt, kPvEncryptInfo, encrypt_key_)) {
        fail(1, response_out);
        return;
    }

    std::vector<uint8_t> sign_data;
    append(sign_data, own_public_, sizeof(own_public_));
    append(sign_data, identity_.pairing_id);
    append(sign_data, peer_public_, sizeof(peer_public_));
    uint8_t signature[crypto::kEd25519SignatureBytes];
    crypto::ed25519Sign(identity_.keys.secret_key, &sign_data[0], sign_data.size(), signature);

    Items sub;
    sub.push_back(tlv8::Item::fromString(tlv8::kTagIdentifier, identity_.pairing_id));
    sub.push_back(tlv8::Item(tlv8::kTagSignature, signature, sizeof(signature)));
    std::vector<uint8_t> sub_bytes = tlv8::encode(sub);
    uint8_t nonce[crypto::kNonceBytes];
    std::vector<uint8_t> sealed;
    ok = labelNonce(kPvMsg02, nonce) &&
         crypto::chacha20Poly1305Seal(encrypt_key_, nonce, NULL, 0, ptrOf(sub_bytes),
                                      sub_bytes.size(), sealed);
    wipeVector(sub_bytes);
    if (!ok) {
        fail(1, response_out);
        return;
    }

    Items reply;
    reply.push_back(tlv8::Item::fromByte(tlv8::kTagState, 2));
    reply.push_back(tlv8::Item(tlv8::kTagPublicKey, own_public_, sizeof(own_public_)));
    reply.push_back(tlv8::Item(tlv8::kTagEncryptedData, sealed));
    response_out = tlv8::encode(reply);
    stage_ = kAwaitM3;
}

void PairVerify::onM3(const Items& items, std::vector<uint8_t>& response_out) {
    const tlv8::Item* encrypted = tlv8::findFirst(items, tlv8::kTagEncryptedData);
    if (stage_ != kAwaitM3 || encrypted == NULL) {
        fail(4, response_out);
        return;
    }

    uint8_t nonce[crypto::kNonceBytes];
    std::vector<uint8_t> plain;
    std::vector<uint8_t> sign_data;
    Items sub;
    uint8_t result_state = 0;
    std::string controller_id;

    do {
        if (!labelNonce(kPvMsg03, nonce) ||
            !crypto::chacha20Poly1305Open(encrypt_key_, nonce, NULL, 0, ptrOf(encrypted->value),
                                          encrypted->value.size(), plain)) {
            result_state = 3;  // reference: chachaOpen throws -> err(request state)
            break;
        }
        result_state = 4;
        if (!tlv8::decode(ptrOf(plain), plain.size(), sub)) {
            break;
        }
        const tlv8::Item* id = tlv8::findFirst(sub, tlv8::kTagIdentifier);
        const tlv8::Item* sig = tlv8::findFirst(sub, tlv8::kTagSignature);
        if (!validControllerId(id) || sig == NULL ||
            sig->value.size() != crypto::kEd25519SignatureBytes) {
            break;
        }
        controller_id.assign(reinterpret_cast<const char*>(&id->value[0]), id->value.size());
        uint8_t ltpk[crypto::kEd25519PublicKeyBytes];
        if (!store_.get(controller_id, ltpk)) {
            break;
        }
        append(sign_data, peer_public_, sizeof(peer_public_));
        append(sign_data, &id->value[0], id->value.size());
        append(sign_data, own_public_, sizeof(own_public_));
        if (!crypto::ed25519Verify(ltpk, &sign_data[0], sign_data.size(), &sig->value[0])) {
            break;
        }
        if (!deriveControlKeys(shared_, read_key_, write_key_)) {
            break;
        }
        result_state = 0;
    } while (false);

    wipeVector(plain);
    wipeVector(sign_data);
    wipeItems(sub);

    if (result_state != 0) {
        fail(result_state, response_out);
        return;
    }
    crypto::wipe(encrypt_key_, sizeof(encrypt_key_));
    controller_id_ = controller_id;
    stage_ = kVerified;
    Items reply;
    reply.push_back(tlv8::Item::fromByte(tlv8::kTagState, 4));
    response_out = tlv8::encode(reply);
}

}  // namespace pairing
}  // namespace carplay
