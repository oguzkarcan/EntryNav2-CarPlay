#ifndef CARPLAY_CONTROL_CIPHER_HPP
#define CARPLAY_CONTROL_CIPHER_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/ControlCipher.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// ChaCha20-Poly1305 framing for the encrypted AirPlay/CarPlay control (and event) channel,
// a byte-exact port of DiPlay's ControlCipher.kt.
//
// Wire format of every frame:
//
//   [u16 little-endian length L][L bytes ciphertext][16-byte Poly1305 tag]
//
// The two length bytes are the AEAD associated data. The 12-byte nonce is
// crypto::makeCounterNonce(counter) = 4 zero bytes + 8-byte little-endian counter. Each direction
// has its own 32-byte key and its own counter, both starting at 0 and incremented once per frame.
//
// Writing splits plaintext into chunks of at most kMaxPayload (0x4000) bytes; an EMPTY plaintext
// still produces exactly one zero-length (18-byte) frame, matching the reference's do/while loop.
// Reading accepts any u16 length (0..65535).
//
// Pure byte-in/byte-out; no sockets, threads or OS dependencies. Not thread-safe.

#include <stddef.h>
#include <stdint.h>
#include <vector>

#include "carplay/airplay_crypto.hpp"

namespace carplay {

class ControlCipher {
public:
    static const size_t kHeaderBytes = 2;
    static const size_t kTagBytes = 16;
    static const size_t kMaxPayload = 0x4000;  // write-side chunk size
    static const size_t kMaxFrameBytes = kHeaderBytes + 0xffff + kTagBytes;  // largest readable frame

    /// Copies both 32-byte keys. readKey decrypts incoming frames, writeKey encrypts outgoing ones.
    ControlCipher(const uint8_t read_key[crypto::kKeyBytes], const uint8_t write_key[crypto::kKeyBytes]);

    /// Wipes both keys and any buffered bytes.
    ~ControlCipher();

    /// Encrypts plaintext and APPENDS one or more frames to `out`. Returns false (and leaves `out`
    /// unchanged) if the cipher has failed, if plaintext is NULL with len > 0, or if the write
    /// counter would overflow (the latter makes the cipher permanently failed).
    bool encrypt(const uint8_t* plaintext, size_t len, std::vector<uint8_t>& out);

    /// Convenience overload.
    bool encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& out);

    /// Streaming decrypt. Consumes all of `data`, APPENDS the plaintext of every complete frame to
    /// `plaintext_out`, and buffers a trailing partial frame internally for the next call.
    ///
    /// Failure semantics (fatal): if a frame fails authentication (or the read counter would
    /// overflow), feed() returns false, the cipher becomes permanently failed (every later feed() and
    /// encrypt() returns false), both keys and the internal buffer are wiped, and no plaintext of the
    /// bad frame is appended. Plaintext of frames that decrypted successfully EARLIER IN THE SAME CALL
    /// remains appended to `plaintext_out` (the caller may use or discard it). The read counter only
    /// advances on successfully authenticated frames.
    ///
    /// Returns false without changing any state if data is NULL with len > 0.
    bool feed(const uint8_t* data, size_t len, std::vector<uint8_t>& plaintext_out);

    /// Convenience overload.
    bool feed(const std::vector<uint8_t>& data, std::vector<uint8_t>& plaintext_out);

    uint64_t readCounter() const { return read_counter_; }
    uint64_t writeCounter() const { return write_counter_; }
    /// Bytes of an incomplete frame currently held (always < kMaxFrameBytes).
    size_t bufferedBytes() const { return buffer_.size(); }
    bool failed() const { return failed_; }

private:
    // Non-copyable: copying would duplicate key material and nonce counters (nonce reuse hazard).
    ControlCipher(const ControlCipher&) = delete;
    ControlCipher& operator=(const ControlCipher&) = delete;

    // Decrypts one complete frame starting at `frame` (header included); appends plaintext.
    bool openFrame(const uint8_t* frame, std::vector<uint8_t>& plaintext_out);
    void fail();

    uint8_t read_key_[crypto::kKeyBytes];
    uint8_t write_key_[crypto::kKeyBytes];
    uint64_t read_counter_;
    uint64_t write_counter_;
    bool failed_;
    std::vector<uint8_t> buffer_;  // incomplete frame bytes only
};

}  // namespace carplay

#endif  // CARPLAY_CONTROL_CIPHER_HPP
