#include "carplay/control_cipher.hpp"

#include <string.h>

namespace carplay {

const size_t ControlCipher::kHeaderBytes;
const size_t ControlCipher::kTagBytes;
const size_t ControlCipher::kMaxPayload;
const size_t ControlCipher::kMaxFrameBytes;

namespace {

const uint64_t kCounterMax = 0xffffffffffffffffULL;

inline size_t frameLength(const uint8_t* header) {
    const size_t payload = static_cast<size_t>(header[0]) | (static_cast<size_t>(header[1]) << 8);
    return ControlCipher::kHeaderBytes + payload + ControlCipher::kTagBytes;
}

}  // namespace

ControlCipher::ControlCipher(const uint8_t read_key[crypto::kKeyBytes],
                             const uint8_t write_key[crypto::kKeyBytes])
    : read_counter_(0), write_counter_(0), failed_(false), buffer_() {
    memcpy(read_key_, read_key, crypto::kKeyBytes);
    memcpy(write_key_, write_key, crypto::kKeyBytes);
}

ControlCipher::~ControlCipher() {
    crypto::wipe(read_key_, sizeof(read_key_));
    crypto::wipe(write_key_, sizeof(write_key_));
    if (!buffer_.empty()) {
        crypto::wipe(&buffer_[0], buffer_.size());
    }
}

void ControlCipher::fail() {
    failed_ = true;
    crypto::wipe(read_key_, sizeof(read_key_));
    crypto::wipe(write_key_, sizeof(write_key_));
    if (!buffer_.empty()) {
        crypto::wipe(&buffer_[0], buffer_.size());
    }
    buffer_.clear();
}

bool ControlCipher::encrypt(const uint8_t* plaintext, size_t len, std::vector<uint8_t>& out) {
    if (failed_ || (plaintext == NULL && len > 0)) {
        return false;
    }
    const uint64_t frames = (len == 0) ? 1 : (static_cast<uint64_t>(len) + kMaxPayload - 1) / kMaxPayload;
    if (frames > kCounterMax - write_counter_) {
        fail();
        return false;
    }

    const size_t original_size = out.size();
    out.reserve(original_size + len + static_cast<size_t>(frames) * (kHeaderBytes + kTagBytes));

    size_t offset = 0;
    do {
        const size_t remaining = len - offset;
        const size_t chunk = remaining < kMaxPayload ? remaining : kMaxPayload;
        const size_t frame_start = out.size();
        out.resize(frame_start + kHeaderBytes + chunk + kTagBytes);
        uint8_t* frame = &out[frame_start];
        frame[0] = static_cast<uint8_t>(chunk & 0xffU);
        frame[1] = static_cast<uint8_t>((chunk >> 8) & 0xffU);

        uint8_t nonce[crypto::kNonceBytes];
        crypto::makeCounterNonce(write_counter_, nonce);
        const bool ok = crypto::chacha20Poly1305SealDetached(
            write_key_, nonce, frame, kHeaderBytes,
            chunk > 0 ? plaintext + offset : NULL, chunk,
            chunk > 0 ? frame + kHeaderBytes : NULL,
            frame + kHeaderBytes + chunk);
        if (!ok) {
            out.resize(original_size);
            return false;
        }
        ++write_counter_;
        offset += chunk;
    } while (offset < len);
    return true;
}

bool ControlCipher::encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& out) {
    return encrypt(plaintext.empty() ? NULL : &plaintext[0], plaintext.size(), out);
}

bool ControlCipher::openFrame(const uint8_t* frame, std::vector<uint8_t>& plaintext_out) {
    if (read_counter_ == kCounterMax) {
        return false;
    }
    const size_t payload = frameLength(frame) - kHeaderBytes - kTagBytes;
    const size_t original_size = plaintext_out.size();
    plaintext_out.resize(original_size + payload);

    uint8_t nonce[crypto::kNonceBytes];
    crypto::makeCounterNonce(read_counter_, nonce);
    const bool ok = crypto::chacha20Poly1305OpenDetached(
        read_key_, nonce, frame, kHeaderBytes,
        payload > 0 ? frame + kHeaderBytes : NULL, payload,
        frame + kHeaderBytes + payload,
        payload > 0 ? &plaintext_out[original_size] : NULL);
    if (!ok) {
        // OpenDetached already wiped the plaintext region on failure.
        plaintext_out.resize(original_size);
        return false;
    }
    ++read_counter_;
    return true;
}

bool ControlCipher::feed(const uint8_t* data, size_t len, std::vector<uint8_t>& plaintext_out) {
    if (failed_) {
        return false;
    }
    if (data == NULL && len > 0) {
        return false;
    }

    size_t pos = 0;

    // 1) Complete a previously buffered partial frame, copying only the bytes it still needs.
    if (!buffer_.empty()) {
        if (buffer_.size() < kHeaderBytes) {
            const size_t need = kHeaderBytes - buffer_.size();
            const size_t take = (len - pos) < need ? (len - pos) : need;
            buffer_.insert(buffer_.end(), data + pos, data + pos + take);
            pos += take;
            if (buffer_.size() < kHeaderBytes) {
                return true;
            }
        }
        const size_t frame_len = frameLength(&buffer_[0]);
        const size_t need = frame_len - buffer_.size();
        const size_t take = (len - pos) < need ? (len - pos) : need;
        if (take > 0) {
            if (buffer_.capacity() < frame_len) {
                buffer_.reserve(frame_len);
            }
            buffer_.insert(buffer_.end(), data + pos, data + pos + take);
            pos += take;
        }
        if (buffer_.size() < frame_len) {
            return true;
        }
        if (!openFrame(&buffer_[0], plaintext_out)) {
            fail();
            return false;
        }
        buffer_.clear();
    }

    // 2) Decrypt complete frames directly from the caller's input (no copy).
    while (len - pos >= kHeaderBytes) {
        const size_t frame_len = frameLength(data + pos);
        if (len - pos < frame_len) {
            break;
        }
        if (!openFrame(data + pos, plaintext_out)) {
            fail();
            return false;
        }
        pos += frame_len;
    }

    // 3) Buffer the trailing partial frame (< kMaxFrameBytes bytes).
    if (pos < len) {
        if (len - pos >= kHeaderBytes) {
            buffer_.reserve(frameLength(data + pos));
        }
        buffer_.insert(buffer_.end(), data + pos, data + len);
    }
    return true;
}

bool ControlCipher::feed(const std::vector<uint8_t>& data, std::vector<uint8_t>& plaintext_out) {
    return feed(data.empty() ? NULL : &data[0], data.size(), plaintext_out);
}

}  // namespace carplay
