#include "carplay/platform/media_engine.hpp"

#include <math.h>
#include <string.h>

#include "carplay/airplay_crypto.hpp"
#include "carplay/ntp_timing.hpp"

namespace carplay {
namespace platform {

namespace {

static const int32_t kStreamTypeMainAudio = 100;
static const int32_t kStreamTypeAltAudio = 101;
static const int32_t kStreamTypeMainHighAudio = 102;
static const int32_t kStreamTypeMainScreen = 110;
static const int32_t kStreamTypeAltScreen = 111;
static const int32_t kStreamTypeData = 130;

static const char kIapDataStreamUuid[] = "E9459FD0-BCAD-4C45-820F-1E72447EF2F2";
static const size_t kIapFrameHeaderBytes = 2U;
static const size_t kIapTagBytes = 16U;
static const size_t kIapPackageHeaderBytes = 32U;
static const size_t kIapMessageTypeOffset = 16U;
static const uint32_t kIapMsgTypeComm = 0x636f6d6dU;  // 'comm'

// Work done per readiness callback is bounded so that one busy (or hostile) socket cannot keep
// the single reactor thread away from the other sockets and the timers. poll() is level
// triggered: whatever is left is picked up in the next round.
static const int kMaxAcceptsPerWakeup = 8;
static const int kMaxTcpReadsPerWakeup = 32;
static const int kMaxDatagramsPerWakeup = 64;

static const size_t kScreenReadChunkBytes = 64U * 1024U;
static const size_t kIapReadChunkBytes = 16U * 1024U;  // IapTunnel.kt READ_CHUNK_BYTES
static const size_t kCompactThresholdBytes = 64U * 1024U;

uint16_t readU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t readU32Be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

std::string toUpperAscii(const std::string& s) {
    std::string out(s);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(out[i]);
        if (c >= 'a' && c <= 'z') {
            out[i] = static_cast<char>(c - 'a' + 'A');
        }
    }
    return out;
}

bool isScreenStreamType(int32_t type) {
    return type == kStreamTypeMainScreen || type == kStreamTypeAltScreen;
}

bool isRealtimeAudioStreamType(int32_t type) {
    return type == kStreamTypeMainAudio ||
           type == kStreamTypeAltAudio ||
           type == kStreamTypeMainHighAudio;
}

// ScreenStream.kt startsWithStartCode: ONLY the 4-byte start code counts. A 3-byte test
// (00 00 01) would also match the length prefix of every first NAL of 256..511 bytes
// (00 00 01 xx) and leave such frames unconverted.
bool startsWithStartCode(const uint8_t* data, size_t len) {
    return len >= 4U && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1;
}

// ScreenCodec.lengthPrefixedToAnnexB: replaces each 4-byte NAL length with 00 00 00 01, but only
// if every length-prefixed NAL fits exactly in the payload; otherwise the payload keeps its
// original bytes for the decoder's normal error path.
void convertFrameToAnnexBIfValid(std::vector<uint8_t>& payload) {
    if (payload.size() < 4U || startsWithStartCode(&payload[0], payload.size())) {
        return;
    }
    size_t offset = 0;
    while (offset + 4U <= payload.size()) {
        const uint32_t nal_len = readU32Be(&payload[offset]);
        offset += 4U;
        if (nal_len == 0 || nal_len > payload.size() - offset) {
            return;
        }
        offset += nal_len;
    }
    if (offset != payload.size()) {
        return;
    }
    stream::lengthPrefixedToAnnexBInPlace(&payload[0], payload.size());
}

// Strips an outer ISO BMFF atom box header if "avcC" or "hvcC" appears at index >= 4
// (ScreenCodec.detectConfig in ScreenStream.kt:200-207). The fourcc found decides the codec.
void stripCodecBoxWrapper(const uint8_t* body,
                          size_t body_len,
                          const uint8_t*& config_ptr_out,
                          size_t& config_len_out,
                          stream::VideoCodecType& box_codec_out) {
    config_ptr_out = body;
    config_len_out = body_len;
    box_codec_out = stream::CODEC_UNKNOWN;
    if (body == NULL || body_len < 8U) {
        return;
    }
    for (size_t idx = 4U; idx + 4U <= body_len; ++idx) {
        if (memcmp(body + idx, "hvcC", 4U) == 0) {
            config_ptr_out = body + idx + 4U;
            config_len_out = body_len - (idx + 4U);
            box_codec_out = stream::CODEC_HEVC_HVCC;
            return;
        }
        if (memcmp(body + idx, "avcC", 4U) == 0) {
            config_ptr_out = body + idx + 4U;
            config_len_out = body_len - (idx + 4U);
            box_codec_out = stream::CODEC_H264_AVCC;
            return;
        }
    }
}

// unsignedPlistInteger / BplistCodec.encodeUnsignedInt of the reference: an unsigned 64-bit value
// travels as an ordinary bplist integer of at most 8 bytes, i.e. a value >= 2^63 is marker 0x13
// plus its raw bits. That is also the form the iPhone itself sends (Session::plistUnsignedId reads
// it back as unsigned). bplist::Value::makeUInt() would emit the 16-byte 0x14 form instead, which
// the reference never puts on the wire; NTP timestamps are >= 2^63 for the whole current NTP era,
// so every /feedback answer depends on this.
bplist::Value makeUnsignedPlistInteger(uint64_t v) {
    return bplist::Value::makeInt(static_cast<int64_t>(v));
}

void unregisterAndClose(Reactor& reactor, TcpListener& listener) {
    if (listener.isOpen()) {
        reactor.remove(listener.handle());
        listener.close();
    }
}

void unregisterAndClose(Reactor& reactor, TcpConnection& conn) {
    if (conn.isOpen()) {
        reactor.remove(conn.handle());
        conn.close();
    }
}

void unregisterAndClose(Reactor& reactor, UdpSocket& sock) {
    if (sock.isOpen()) {
        reactor.remove(sock.handle());
        sock.close();
    }
}

// ---------------------------------------------------------------------------------------------
// Slot lifetime
//
// MediaSink callbacks run from inside a slot's own reactor callback and may re-enter the engine:
// sink -> SessionServer::closeActiveSession() -> Session::close() -> onSessionClosed() releases
// every slot, including the one whose member function is still on the stack. A slot is therefore
// never deleted while it dispatches: releaseSlot() closes it (no further callbacks, `closing`
// set) and the outermost DispatchScope deletes it on the way out. Slot code checks `closing`
// after every sink callback and returns without touching anything else.
// ---------------------------------------------------------------------------------------------

struct SlotLifetime {
    bool closing;        // close() ran: sockets and timers are gone, deliver nothing further
    bool doomed;         // released while dispatching: delete when dispatch_depth returns to 0
    int dispatch_depth;

    SlotLifetime() : closing(false), doomed(false), dispatch_depth(0) {}
};

template <typename SlotT>
void releaseSlot(SlotT* slot) {
    if (slot == NULL) {
        return;
    }
    slot->close();
    if (slot->dispatch_depth > 0) {
        slot->doomed = true;
    } else {
        delete slot;
    }
}

template <typename SlotT>
class DispatchScope {
public:
    explicit DispatchScope(SlotT* slot) : slot_(slot) { slot_->dispatch_depth += 1; }
    ~DispatchScope() {
        slot_->dispatch_depth -= 1;
        if (slot_->dispatch_depth == 0 && slot_->doomed) {
            delete slot_;
        }
    }

private:
    DispatchScope(const DispatchScope&) = delete;
    DispatchScope& operator=(const DispatchScope&) = delete;
    SlotT* slot_;
};

}  // namespace

// =============================================================================================
// ScreenSlot (stream types 110 / 111)
// =============================================================================================

struct MediaEngine::ScreenSlot : public IoHandler, public SlotLifetime {
    MediaEngine* engine;
    int32_t type;
    uint8_t key[crypto::kKeyBytes];
    uint64_t frame_counter;
    TcpListener listener;
    TcpConnection conn;
    std::vector<uint8_t> rx_buf;
    size_t rx_head;
    std::vector<uint8_t> frame_plain;  // reused across frames
    std::vector<uint8_t> annexb_cfg;

    ScreenSlot(MediaEngine* eng, int32_t t, const uint8_t k[crypto::kKeyBytes])
        : engine(eng), type(t), frame_counter(0), rx_head(0) {
        memcpy(key, k, crypto::kKeyBytes);
    }

    virtual ~ScreenSlot() {
        close();
        crypto::wipe(key, sizeof(key));
    }

    // Idempotent. Keeps the buffers: a sink callback further up the stack may still read them.
    void close() {
        closing = true;
        unregisterAndClose(engine->reactor_, conn);
        unregisterAndClose(engine->reactor_, listener);
    }

    static bool acceptFilter(void* ctx, const Address& peer) {
        ScreenSlot* self = static_cast<ScreenSlot*>(ctx);
        if (self->closing || self->conn.isOpen()) {
            return false;
        }
        if (!self->engine->peerAllowed(peer)) {
            self->engine->screen_rejected_peers_ += 1;
            return false;
        }
        return true;
    }

    // The listener and the connection share this handler; only one of them is open at a time
    // (the listener closes when the one screen connection has been accepted).
    virtual void onReadable() {
        DispatchScope<ScreenSlot> scope(this);
        if (closing) {
            return;
        }
        if (conn.isOpen()) {
            onDataReady();
        } else if (listener.isOpen()) {
            onAcceptReady();
        }
    }

    virtual void onError() {
        DispatchScope<ScreenSlot> scope(this);
        terminate();
    }

    void onAcceptReady() {
        for (int n = 0; n < kMaxAcceptsPerWakeup; ++n) {
            const TcpListener::AcceptResult ar = listener.accept(conn);
            if (ar == TcpListener::kRejected) {
                continue;
            }
            if (ar != TcpListener::kAccepted) {
                return;
            }
            // Only one screen connection per SETUP: close the listener once accepted.
            unregisterAndClose(engine->reactor_, listener);
            conn.setLingerZero();
            conn.setNoDelay(true);
            if (!engine->reactor_.add(conn.handle(), this, kPollIn)) {
                terminate();
            }
            return;
        }
    }

    void onDataReady();
    bool processMessages();
    void terminate();
};

// =============================================================================================
// AudioSlot (stream types 100 / 101 / 102)
// =============================================================================================

struct MediaEngine::AudioSlot : public IoHandler, public TimerHandler, public SlotLifetime {
    MediaEngine* engine;
    AudioStreamId id;
    audio::AudioFormat format;
    uint8_t output_key[crypto::kKeyBytes];
    bool has_connection_id;
    uint64_t connection_id;
    int32_t playout_latency_ms;

    UdpSocket data_sock;
    UdpSocket ctrl_sock;
    audio::JitterBuffer jitter;
    std::vector<uint8_t> decrypted_payload;
    std::vector<int16_t> pcm_samples;

    bool started;
    uint32_t first_sample;
    int64_t origin_mono_ns;

    bool mic_wanted;
    bool mic_started;
    uint32_t mic_silent_timer_id;
    Address mic_dest;
    audio::MicStreamParams mic_params;
    audio::MicPacketizer mic_packetizer;

    // The RTCP control port is bound because the phone expects it; like AudioStream.kt runControl
    // its datagrams are read and discarded.
    struct CtrlHandler : public IoHandler {
        AudioSlot* slot;
        explicit CtrlHandler(AudioSlot* s) : slot(s) {}
        virtual void onReadable() { slot->onControlReadable(); }
        virtual void onError() {}
    } ctrl_handler;

    AudioSlot(MediaEngine* eng,
              const AudioStreamId& stream_id,
              const audio::AudioFormat& fmt,
              const uint8_t out_key[crypto::kKeyBytes],
              bool has_conn_id,
              uint64_t conn_id,
              int32_t latency_ms,
              size_t jitter_cap,
              uint16_t jitter_depth)
        : engine(eng),
          id(stream_id),
          format(fmt),
          has_connection_id(has_conn_id),
          connection_id(conn_id),
          playout_latency_ms(latency_ms),
          jitter(jitter_cap, jitter_depth),
          started(false),
          first_sample(0),
          origin_mono_ns(0),
          mic_wanted(false),
          mic_started(false),
          mic_silent_timer_id(Reactor::kNoTimer),
          ctrl_handler(this) {
        memcpy(output_key, out_key, crypto::kKeyBytes);
    }

    virtual ~AudioSlot() {
        close();
        crypto::wipe(output_key, sizeof(output_key));
    }

    // Idempotent. Wipes the uplink key (MicPacketizer::reset); the downlink key goes with the slot.
    void close() {
        closing = true;
        if (mic_silent_timer_id != Reactor::kNoTimer) {
            engine->reactor_.cancelTimer(mic_silent_timer_id);
            mic_silent_timer_id = Reactor::kNoTimer;
        }
        unregisterAndClose(engine->reactor_, data_sock);
        unregisterAndClose(engine->reactor_, ctrl_sock);
        mic_packetizer.reset();
    }

    // MicrophoneStart: at most once, by the first downlink packet or the silent-start timer,
    // whichever comes first. The sink callback is the last thing done here: it may release
    // this slot.
    void triggerMicrophoneStart() {
        if (closing || !mic_wanted || mic_started) {
            return;
        }
        if (mic_silent_timer_id != Reactor::kNoTimer) {
            engine->reactor_.cancelTimer(mic_silent_timer_id);
            mic_silent_timer_id = Reactor::kNoTimer;
        }
        mic_started = true;
        engine->sink_.onMicrophoneStarted(id, mic_params, mic_dest);
    }

    virtual void onTimer(uint32_t timer_id) {
        DispatchScope<AudioSlot> scope(this);
        if (closing || timer_id != mic_silent_timer_id) {
            return;
        }
        mic_silent_timer_id = Reactor::kNoTimer;
        triggerMicrophoneStart();
    }

    virtual void onReadable() {
        DispatchScope<AudioSlot> scope(this);
        uint8_t buf[4096];  // AudioStream.kt DATAGRAM_BYTES
        audio::JitterBuffer::Packet pkt;
        for (int n = 0; n < kMaxDatagramsPerWakeup && !closing; ++n) {
            size_t got = 0;
            Address from;
            const IoStatus st = data_sock.receiveFrom(buf, sizeof(buf), got, from);
            if (st == kIoTruncated) {
                continue;  // longer than any CarPlay audio datagram: cannot authenticate, drop
            }
            if (st != kIoOk) {
                return;  // kIoWouldBlock (drained) or a socket error
            }
            if (!engine->peerAllowed(from)) {
                engine->audio_stranger_drops_ += 1;
                continue;
            }
            audio::RtpHeader hdr;
            if (audio::openPacket(output_key, buf, got, hdr, decrypted_payload) != audio::kOpenOk) {
                engine->audio_auth_failures_ += 1;
                continue;
            }
            if (!started) {
                started = true;
                first_sample = hdr.timestamp;
                origin_mono_ns = engine->reactor_.now();
                engine->sink_.onAudioStarted(id, format, first_sample);
                if (closing) {
                    return;
                }
                triggerMicrophoneStart();
                if (closing) {
                    return;
                }
            }
            const uint8_t* payload_ptr =
                decrypted_payload.empty() ? NULL : &decrypted_payload[0];
            engine->sink_.onAudioRtp(id, format, hdr, payload_ptr, decrypted_payload.size());
            if (closing) {
                return;
            }

            if (format.codec != audio::kCodecLpcm) {
                continue;  // AAC-LC / Opus: the sink decodes from onAudioRtp
            }
            jitter.push(hdr.sequence, hdr.timestamp, payload_ptr, decrypted_payload.size());
            for (;;) {
                const audio::JitterBuffer::PopResult pop_res = jitter.pop(pkt);
                if (pop_res == audio::JitterBuffer::kPopEmpty) {
                    break;
                }
                if (pop_res == audio::JitterBuffer::kPopLost) {
                    engine->sink_.onAudioPacketLost(id, format, pkt.sequence);
                    if (closing) {
                        return;
                    }
                    continue;
                }
                const uint8_t* p = pkt.payload.empty() ? NULL : &pkt.payload[0];
                audio::lpcmToInt16(p, pkt.payload.size(), pcm_samples, audio::kBigEndianSamples);
                const int16_t* s_ptr = pcm_samples.empty() ? NULL : &pcm_samples[0];
                engine->sink_.onAudioPcm(
                    id, format, s_ptr, pcm_samples.size(), pkt.sequence, pkt.timestamp);
                if (closing) {
                    return;
                }
            }
        }
    }

    void onControlReadable() {
        uint8_t buf[2048];
        for (int n = 0; n < kMaxDatagramsPerWakeup; ++n) {
            size_t got = 0;
            Address from;
            const IoStatus st = ctrl_sock.receiveFrom(buf, sizeof(buf), got, from);
            if (st != kIoOk && st != kIoTruncated) {
                return;
            }
        }
    }

    virtual void onError() {}
};

// =============================================================================================
// IapSlot (stream type 130)
// =============================================================================================

struct MediaEngine::IapSlot : public IoHandler, public SlotLifetime {
    MediaEngine* engine;
    uint8_t read_key[crypto::kKeyBytes];
    uint64_t read_counter;
    TcpListener listener;
    TcpConnection conn;
    std::vector<uint8_t> cipher_buf;
    size_t cipher_head;
    std::vector<uint8_t> plain_buf;
    size_t plain_head;

    IapSlot(MediaEngine* eng, const uint8_t key[crypto::kKeyBytes])
        : engine(eng), read_counter(0), cipher_head(0), plain_head(0) {
        memcpy(read_key, key, crypto::kKeyBytes);
    }

    virtual ~IapSlot() {
        close();
        crypto::wipe(read_key, sizeof(read_key));
    }

    // Idempotent. Keeps the buffers: a sink callback further up the stack may still read them.
    void close() {
        closing = true;
        unregisterAndClose(engine->reactor_, conn);
        unregisterAndClose(engine->reactor_, listener);
    }

    void resetStreamState() {
        read_counter = 0;
        cipher_buf.clear();
        cipher_head = 0;
        plain_buf.clear();
        plain_head = 0;
    }

    static bool acceptFilter(void* ctx, const Address& peer) {
        IapSlot* self = static_cast<IapSlot*>(ctx);
        if (self->closing || self->conn.isOpen()) {
            return false;
        }
        return self->engine->peerAllowed(peer);
    }

    // The listener and the connection share this handler. While a connection is open the
    // listener stays bound but is not polled (interest 0), so only one of them can be ready:
    // like IapTunnel.kt, whose accept thread is busy in run(), a further connection waits in the
    // backlog until the current one ends.
    virtual void onReadable() {
        DispatchScope<IapSlot> scope(this);
        if (closing) {
            return;
        }
        if (conn.isOpen()) {
            onDataReady();
        } else if (listener.isOpen()) {
            onAcceptReady();
        }
    }

    virtual void onError() {
        DispatchScope<IapSlot> scope(this);
        terminateFatal();
    }

    void onAcceptReady() {
        for (int n = 0; n < kMaxAcceptsPerWakeup; ++n) {
            const TcpListener::AcceptResult ar = listener.accept(conn);
            if (ar == TcpListener::kRejected) {
                continue;
            }
            if (ar != TcpListener::kAccepted) {
                return;
            }
            conn.setLingerZero();
            conn.setNoDelay(true);
            resetStreamState();  // IapTunnel.kt accept(): readCounter.set(0) per connection
            if (!engine->reactor_.add(conn.handle(), this, kPollIn)) {
                terminateFatal();
                return;
            }
            engine->reactor_.modify(listener.handle(), 0);
            return;
        }
    }

    void onDataReady() {
        for (int n = 0; n < kMaxTcpReadsPerWakeup; ++n) {
            const IoStatus st = conn.readAppend(cipher_buf, kIapReadChunkBytes);
            if (st == kIoWouldBlock) {
                return;
            }
            if (st == kIoClosed) {
                onPeerEof();
                return;
            }
            if (st != kIoOk || !processCiphertext()) {
                terminateFatal();  // no-op when a sink callback already released this slot
                return;
            }
            if (closing) {
                return;
            }
        }
    }

    // IapTunnel.kt run(): a clean EOF is not a failure (onClosed is not called). The connection
    // goes away with whatever partial frame it left behind and the accept loop continues.
    void onPeerEof() {
        unregisterAndClose(engine->reactor_, conn);
        resetStreamState();
        if (listener.isOpen()) {
            engine->reactor_.modify(listener.handle(), kPollIn);
        }
    }

    // false = authentication or framing failure (fatal). true with `closing` set = a sink
    // callback released this slot: the caller must return at once.
    bool processCiphertext() {
        while (cipher_buf.size() - cipher_head >= kIapFrameHeaderBytes) {
            const uint8_t* frame_ptr = &cipher_buf[cipher_head];
            const size_t pt_len = readU16Le(frame_ptr);
            const size_t total_frame = kIapFrameHeaderBytes + pt_len + kIapTagBytes;
            if (cipher_buf.size() - cipher_head < total_frame) {
                break;
            }
            uint8_t nonce[crypto::kNonceBytes];
            crypto::makeCounterNonce(read_counter, nonce);

            const size_t old_plain_size = plain_buf.size();
            plain_buf.resize(old_plain_size + pt_len);
            uint8_t* out_ptr = pt_len > 0 ? &plain_buf[old_plain_size] : NULL;
            const uint8_t* ct_ptr = frame_ptr + kIapFrameHeaderBytes;
            const uint8_t* tag_ptr = ct_ptr + pt_len;

            if (!crypto::chacha20Poly1305OpenDetached(
                    read_key, nonce, frame_ptr, kIapFrameHeaderBytes, ct_ptr, pt_len, tag_ptr, out_ptr)) {
                plain_buf.resize(old_plain_size);
                return false;
            }
            read_counter += 1;
            cipher_head += total_frame;
        }
        if (cipher_head == cipher_buf.size()) {
            cipher_buf.clear();
            cipher_head = 0;
        } else if (cipher_head >= kCompactThresholdBytes) {
            cipher_buf.erase(cipher_buf.begin(),
                             cipher_buf.begin() + static_cast<ptrdiff_t>(cipher_head));
            cipher_head = 0;
        }

        while (plain_buf.size() - plain_head >= kIapPackageHeaderBytes) {
            const uint8_t* pkg_ptr = &plain_buf[plain_head];
            const uint32_t pkg_size = readU32Be(pkg_ptr);
            if (pkg_size < kIapPackageHeaderBytes ||
                pkg_size > engine->config_.max_iap_package_bytes) {
                return false;
            }
            if (plain_buf.size() - plain_head < pkg_size) {
                break;
            }
            const uint32_t msg_type = readU32Be(pkg_ptr + kIapMessageTypeOffset);
            plain_head += pkg_size;  // consumed before the callback, which may release this slot
            if (msg_type == kIapMsgTypeComm) {
                const size_t body_len = static_cast<size_t>(pkg_size) - kIapPackageHeaderBytes;
                const uint8_t* body_ptr = body_len > 0 ? (pkg_ptr + kIapPackageHeaderBytes) : NULL;
                engine->sink_.onIapMessage(body_ptr, body_len);
                if (closing) {
                    return true;
                }
            }
        }
        if (plain_head == plain_buf.size()) {
            plain_buf.clear();
            plain_head = 0;
        } else if (plain_head >= kCompactThresholdBytes) {
            plain_buf.erase(plain_buf.begin(),
                            plain_buf.begin() + static_cast<ptrdiff_t>(plain_head));
            plain_head = 0;
        }
        return true;
    }

    // IapTunnel.Listener.onClosed(failure) -> session.close(). Only called while dispatching.
    void terminateFatal() {
        if (closing) {
            return;
        }
        MediaEngine* eng = engine;
        if (eng->iap_stream_ == this) {
            eng->iap_stream_ = NULL;
        }
        releaseSlot(this);  // closed now, deleted by the DispatchScope
        if (!eng->shutting_down_) {
            eng->requestSessionClose();
        }
    }
};

// =============================================================================================
// ScreenSlot methods
// =============================================================================================

void MediaEngine::ScreenSlot::onDataReady() {
    for (int n = 0; n < kMaxTcpReadsPerWakeup; ++n) {
        const IoStatus st = conn.readAppend(rx_buf, kScreenReadChunkBytes);
        if (st == kIoWouldBlock) {
            return;
        }
        // ScreenStream.kt run(): EOF, a read error, an oversized body and a decrypt failure all
        // end in onClosed -> session.close().
        if (st != kIoOk || !processMessages()) {
            terminate();  // no-op when a sink callback already released this slot
            return;
        }
        if (closing) {
            return;
        }
    }
}

// false = fatal. true with `closing` set = a sink callback released this slot: the caller must
// return at once.
bool MediaEngine::ScreenSlot::processMessages() {
    while (rx_buf.size() - rx_head >= stream::kScreenHeaderBytes) {
        const uint8_t* hdr_ptr = &rx_buf[rx_head];
        stream::ScreenPacketHeader hdr;
        if (!stream::parseScreenHeader(hdr_ptr, stream::kScreenHeaderBytes, hdr)) {
            return false;
        }
        if (hdr.payload_size > engine->config_.max_screen_payload_bytes) {
            return false;
        }
        const size_t body_len = static_cast<size_t>(hdr.payload_size);
        const size_t total_msg = stream::kScreenHeaderBytes + body_len;
        if (rx_buf.size() - rx_head < total_msg) {
            break;
        }
        const int64_t arrival_ns = engine->reactor_.now();
        const uint8_t* body_ptr = hdr_ptr + stream::kScreenHeaderBytes;
        rx_head += total_msg;  // consumed before the callbacks, which may release this slot

        if (hdr.opcode == stream::kOpVideoFrame) {
            if (body_len < crypto::kTagBytes) {
                continue;  // ScreenStream.kt:103: ignored, the frame counter does not advance
            }
            const size_t ct_len = body_len - crypto::kTagBytes;
            if (!stream::decryptFrame(key,
                                      frame_counter,
                                      hdr_ptr,
                                      stream::kScreenHeaderBytes,
                                      body_ptr,
                                      ct_len,
                                      body_ptr + ct_len,
                                      frame_plain)) {
                return false;
            }
            frame_counter += 1;
            convertFrameToAnnexBIfValid(frame_plain);
            const uint8_t* f_ptr = frame_plain.empty() ? NULL : &frame_plain[0];
            engine->sink_.onVideoFrame(
                type, f_ptr, frame_plain.size(), hdr.sender_nanos, arrival_ns);
            if (closing) {
                return true;
            }
        } else if (hdr.opcode == stream::kOpVideoConfig) {
            const uint8_t* cfg_ptr = NULL;
            size_t cfg_len = 0;
            // ScreenCodec.detectConfig: an avcC / hvcC box decides the codec. Only a bare record
            // is classified by its content (the reference then knows just "avcC-like or HEVC";
            // detectConfigCodec additionally recognises Annex B and reports UNKNOWN otherwise).
            stream::VideoCodecType codec = stream::CODEC_UNKNOWN;
            stripCodecBoxWrapper(body_ptr, body_len, cfg_ptr, cfg_len, codec);
            if (codec == stream::CODEC_UNKNOWN) {
                codec = stream::detectConfigCodec(cfg_ptr, cfg_len);
            }
            annexb_cfg.clear();
            if (codec == stream::CODEC_H264_AVCC) {
                stream::avcCToAnnexB(cfg_ptr, cfg_len, annexb_cfg);
            } else if (codec == stream::CODEC_ANNEX_B && cfg_ptr != NULL && cfg_len > 0) {
                annexb_cfg.assign(cfg_ptr, cfg_ptr + cfg_len);
            }
            const uint8_t* ab_ptr = annexb_cfg.empty() ? NULL : &annexb_cfg[0];
            engine->sink_.onVideoConfig(type,
                                        codec,
                                        ab_ptr,
                                        annexb_cfg.size(),
                                        cfg_len > 0 ? cfg_ptr : NULL,
                                        cfg_len,
                                        hdr.width_px,
                                        hdr.height_px);
            if (closing) {
                return true;
            }
        }
        // Any other opcode: skipped (ScreenStream.kt onMessage has no else branch).
    }

    if (rx_head == rx_buf.size()) {
        rx_buf.clear();
        rx_head = 0;
    } else if (rx_head >= kCompactThresholdBytes) {
        rx_buf.erase(rx_buf.begin(), rx_buf.begin() + static_cast<ptrdiff_t>(rx_head));
        rx_head = 0;
    }
    return true;
}

// ScreenStream.Listener.onClosed in CarPlayMediaEngine.kt:160-169: report the screen inactive
// if this is still the current stream of its type, then close the session. Only called while
// dispatching.
void MediaEngine::ScreenSlot::terminate() {
    if (closing) {
        return;
    }
    MediaEngine* eng = engine;
    const int32_t stream_type = type;
    bool removed = false;
    for (size_t i = 0; i < eng->screens_.size(); ++i) {
        if (eng->screens_[i] == this) {
            eng->screens_.erase(eng->screens_.begin() + static_cast<ptrdiff_t>(i));
            removed = true;
            break;
        }
    }
    releaseSlot(this);  // closed now, deleted by the DispatchScope
    if (eng->shutting_down_) {
        return;
    }
    if (removed) {
        eng->sink_.onScreenStreamActive(stream_type, false);
    }
    eng->requestSessionClose();
}

// =============================================================================================
// MediaEngine
// =============================================================================================

MediaEngine::MediaEngine(Reactor& reactor,
                         MediaSink& sink,
                         const MediaEngineConfig& config)
    : reactor_(reactor),
      sink_(sink),
      config_(config),
      synced_ntp_fn_(NULL),
      synced_ntp_ctx_(NULL),
      close_session_fn_(NULL),
      close_session_ctx_(NULL),
      iap_stream_(NULL),
      ducked_(false),
      shutting_down_(false),
      audio_auth_failures_(0),
      audio_stranger_drops_(0),
      screen_rejected_peers_(0),
      mic_post_pending_(false) {}

MediaEngine::~MediaEngine() {
    shutting_down_ = true;
    closeAllStreams();
    // A worker-thread submit may have left onMicWorkerPost(this) queued in the reactor.
    reactor_.cancelPosted(&MediaEngine::onMicWorkerPost, this);
}

void MediaEngine::setControlPeer(const Address& peer) {
    control_peer_ = peer;
}

void MediaEngine::setSyncedNtpCallback(SyncedNtpFn fn, void* ctx) {
    synced_ntp_fn_ = fn;
    synced_ntp_ctx_ = ctx;
}

void MediaEngine::setCloseSessionCallback(SessionActionFn fn, void* ctx) {
    close_session_fn_ = fn;
    close_session_ctx_ = ctx;
}

void MediaEngine::clearSessionCallbacks(void* ctx) {
    if (synced_ntp_ctx_ == ctx) {
        synced_ntp_fn_ = NULL;
        synced_ntp_ctx_ = NULL;
    }
    if (close_session_ctx_ == ctx) {
        close_session_fn_ = NULL;
        close_session_ctx_ = NULL;
    }
}

bool MediaEngine::peerAllowed(const Address& from) const {
    if (!config_.enforce_peer_address) {
        return true;
    }
    if (!control_peer_.valid()) {
        return false;
    }
    return from.sameHost(control_peer_);
}

uint64_t MediaEngine::currentSyncedNtp() const {
    if (synced_ntp_fn_ != NULL) {
        return synced_ntp_fn_(synced_ntp_ctx_);
    }
    return ntp::ntpFromNanos(reactor_.now());
}

void MediaEngine::requestSessionClose() {
    if (close_session_fn_ != NULL) {
        close_session_fn_(close_session_ctx_);
    }
}

bool MediaEngine::onScreen(session::Session& session,
                           int32_t type,
                           const bplist::Value& stream,
                           int32_t& data_port_out) {
    if (!isScreenStreamType(type)) {
        return false;
    }
    if (config_.enforce_peer_address && !control_peer_.valid()) {
        return false;
    }
    uint8_t key[crypto::kKeyBytes];
    if (!session.streamOutputKey(stream, key)) {
        return false;
    }

    ScreenSlot* slot = new ScreenSlot(this, type, key);
    crypto::wipe(key, sizeof(key));

    slot->listener.setAcceptFilter(&ScreenSlot::acceptFilter, slot);
    if (!slot->listener.listenAny(0) ||
        !reactor_.add(slot->listener.handle(), slot, kPollIn)) {
        delete slot;
        return false;
    }
    data_port_out = static_cast<int32_t>(slot->listener.port());

    // Replace any existing screen stream of the same type (streams.put(...)?.close()).
    ScreenSlot* old = NULL;
    for (size_t i = 0; i < screens_.size(); ++i) {
        if (screens_[i]->type == type) {
            old = screens_[i];
            screens_[i] = slot;
            break;
        }
    }
    if (old == NULL) {
        screens_.push_back(slot);
    }
    releaseSlot(old);
    sink_.onScreenStreamActive(type, true);  // last: the sink may re-enter
    return true;
}

bool MediaEngine::onAudio(session::Session& session,
                          int32_t type,
                          const bplist::Value& stream,
                          bplist::Value& response_out) {
    if (!isRealtimeAudioStreamType(type)) {
        return false;
    }
    if (config_.enforce_peer_address && !control_peer_.valid()) {
        return false;
    }

    const audio::AudioFormat format = audio::streamAudioFormat(stream, type);
    const AudioStreamId stream_id(type, format.audio_type);

    // A SETUP for an existing (type, audioType) pair first retires the previous stream, before
    // anything that can still decline the new one (CarPlayMediaEngine.kt:183-187).
    for (size_t i = 0; i < audios_.size(); ++i) {
        if (audios_[i]->id == stream_id) {
            AudioSlot* old = audios_[i];
            audios_.erase(audios_.begin() + static_cast<ptrdiff_t>(i));
            retireAudioSlot(old);
            break;
        }
    }
    if (session.closed()) {
        return false;  // a sink callback above closed the session
    }

    if (!info::isSupportedOutputFormat(session.config(), format)) {
        return false;
    }
    if (audios_.size() >= config_.max_audio_streams) {
        return false;
    }

    uint8_t out_key[crypto::kKeyBytes];
    if (!session.streamOutputKey(stream, out_key)) {
        return false;
    }

    uint64_t conn_id = 0;
    bool has_conn_id = false;
    const bplist::Value* cid_val = stream.find("streamConnectionID");
    if (cid_val != NULL) {
        has_conn_id = session::Session::plistUnsignedId(*cid_val, conn_id);
    }

    int32_t latency_ms = 0;
    const bplist::Value* lat_val = stream.find("audioLatencyMs");
    if (lat_val != NULL && !session::plistNumberToInt(*lat_val, latency_ms)) {
        latency_ms = 0;
    }

    AudioSlot* slot = new AudioSlot(this,
                                    stream_id,
                                    format,
                                    out_key,
                                    has_conn_id,
                                    conn_id,
                                    latency_ms,
                                    config_.audio_jitter_capacity,
                                    config_.audio_jitter_reorder_depth);
    crypto::wipe(out_key, sizeof(out_key));

    if (!slot->data_sock.openAny(0) ||
        !slot->ctrl_sock.openAny(0)) {
        delete slot;
        return false;
    }
    size_t granted = 0;
    slot->data_sock.setReceiveBuffer(UdpSocket::kAudioReceiveBuffer, granted);

    if (!reactor_.add(slot->data_sock.handle(), slot, kPollIn) ||
        !reactor_.add(slot->ctrl_sock.handle(), &slot->ctrl_handler, kPollIn)) {
        delete slot;
        return false;
    }

    // Microphone uplink (microphoneConfig, CarPlayMediaEngine.kt:624-663): type 100 only, the
    // stream must ask for input, name a dataPort, and its INPUT key must be derivable.
    audio::MicStreamParams mic_params;
    if (audio::parseMicrophoneStream(
            type, stream, config_.microphone_enabled && session.config().microphone, mic_params) &&
        mic_params.supported &&
        control_peer_.valid()) {
        uint8_t in_key[crypto::kKeyBytes];
        if (session.streamInputKey(stream, in_key)) {
            if (slot->mic_packetizer.configure(mic_params, in_key)) {
                slot->mic_wanted = true;
                slot->mic_params = mic_params;
                slot->mic_dest = control_peer_;
                slot->mic_dest.setPort(static_cast<uint16_t>(mic_params.data_port));
            }
            crypto::wipe(in_key, sizeof(in_key));
        }
    }

    audios_.push_back(slot);

    response_out = bplist::Value::makeDict();
    response_out.set("type", bplist::Value::makeInt(type));
    response_out.set("dataPort",
                     bplist::Value::makeInt(static_cast<int64_t>(slot->data_sock.port())));
    response_out.set("controlPort",
                     bplist::Value::makeInt(static_cast<int64_t>(slot->ctrl_sock.port())));
    response_out.set("streamConnectionID",
                     makeUnsignedPlistInteger(has_conn_id ? conn_id : 0ULL));

    // MicrophoneStart.startsWithoutDownlink: every audioType except "telephony" starts after
    // mic_silent_start_ms even if no downlink packet arrives (a call waits for its downlink, the
    // echo reference). Last step: starting the microphone calls the sink, which may re-enter and
    // release `slot`.
    if (slot->mic_wanted && format.audio_type != "telephony") {
        if (config_.mic_silent_start_ms > 0) {
            slot->mic_silent_timer_id =
                reactor_.startTimer(config_.mic_silent_start_ms, 0, slot);
        }
        if (config_.mic_silent_start_ms == 0 ||
            (config_.mic_silent_start_ms > 0 && slot->mic_silent_timer_id == Reactor::kNoTimer)) {
            slot->triggerMicrophoneStart();  // immediate, also when the timer table is full
        }
    }
    return true;
}

bool MediaEngine::onDataStream(session::Session& session,
                               const bplist::Value& stream,
                               bplist::Value& response_out) {
    if (!stream.isDict()) {
        return false;
    }
    const bplist::Value* uuid_val = stream.find("clientTypeUUID");
    if (uuid_val == NULL || !uuid_val->isString()) {
        return false;
    }
    if (toUpperAscii(uuid_val->asString()) != kIapDataStreamUuid) {
        return false;
    }
    if (config_.enforce_peer_address && !control_peer_.valid()) {
        return false;
    }

    uint8_t read_key[crypto::kKeyBytes];
    if (!session.streamOutputKey(stream, read_key, "seed")) {
        return false;
    }

    IapSlot* slot = new IapSlot(this, read_key);
    crypto::wipe(read_key, sizeof(read_key));

    slot->listener.setAcceptFilter(&IapSlot::acceptFilter, slot);
    if (!slot->listener.listenAny(0) ||
        !reactor_.add(slot->listener.handle(), slot, kPollIn)) {
        delete slot;
        return false;
    }

    IapSlot* old = iap_stream_;
    iap_stream_ = slot;
    releaseSlot(old);

    response_out = bplist::Value::makeDict();
    response_out.set("type", bplist::Value::makeInt(kStreamTypeData));
    response_out.set("streamID", bplist::Value::makeInt(1));
    response_out.set("dataPort",
                     bplist::Value::makeInt(static_cast<int64_t>(slot->listener.port())));
    const bplist::Value* cid_val = stream.find("streamConnectionID");
    uint64_t cid = 0;
    if (cid_val != NULL && session::Session::plistUnsignedId(*cid_val, cid)) {
        response_out.set("streamConnectionID", makeUnsignedPlistInteger(cid));
    }
    return true;
}

bool MediaEngine::onFeedback(session::Session& /*session*/, bplist::Value& response_out) {
    if (audios_.empty()) {
        return false;
    }
    bplist::Value streams_arr = bplist::Value::makeArray();
    const int64_t now_ns = reactor_.now();
    const uint64_t synced_ntp = currentSyncedNtp();

    for (size_t i = 0; i < audios_.size(); ++i) {
        const AudioSlot* slot = audios_[i];
        // sampleTime counts on the stream's RTP clock, not on the decode rate
        // (CarPlayMediaEngine.kt onFeedback).
        const uint32_t clock_rate = slot->format.rtp_clock_rate;
        bplist::Value entry = bplist::Value::makeDict();
        entry.set("type", bplist::Value::makeInt(slot->id.type));
        entry.set("sampleRate", bplist::Value::makeInt(static_cast<int64_t>(clock_rate)));

        if (slot->started) {
            double elapsed_sec =
                static_cast<double>(now_ns - slot->origin_mono_ns) / 1e9 -
                static_cast<double>(slot->playout_latency_ms) / 1000.0;
            if (!(elapsed_sec > 0.0)) {
                elapsed_sec = 0.0;
            }
            const uint64_t advanced =
                static_cast<uint64_t>(floor(elapsed_sec * static_cast<double>(clock_rate) + 0.5));
            const uint64_t sample_time =
                (static_cast<uint64_t>(slot->first_sample) + advanced) & 0xffffffffULL;

            entry.set("streamConnectionID",
                      makeUnsignedPlistInteger(slot->has_connection_id ? slot->connection_id : 0ULL));
            entry.set("timestamp", makeUnsignedPlistInteger(synced_ntp));
            entry.set("timestampRawNs", bplist::Value::makeInt(now_ns));
            entry.set("sampleTime", bplist::Value::makeInt(static_cast<int64_t>(sample_time)));
        }
        streams_arr.asArray().push_back(entry);
    }

    response_out = bplist::Value::makeDict();
    response_out.set("streams", streams_arr);
    return true;
}

void MediaEngine::retireAudioSlot(AudioSlot* slot) {
    const AudioStreamId aid = slot->id;
    const bool had_mic = slot->mic_wanted;
    releaseSlot(slot);
    if (shutting_down_) {
        return;  // the sink may already be gone
    }
    if (had_mic) {
        sink_.onMicrophoneStopped(aid);
    }
    sink_.onAudioStopped(aid);
}

void MediaEngine::onTeardown(session::Session& /*session*/, int32_t type) {
    if (type == kStreamTypeData) {
        IapSlot* old = iap_stream_;
        iap_stream_ = NULL;
        releaseSlot(old);
        return;
    }

    if (isScreenStreamType(type)) {
        bool had_screen = false;
        for (size_t i = 0; i < screens_.size();) {
            if (screens_[i]->type == type) {
                ScreenSlot* s = screens_[i];
                screens_.erase(screens_.begin() + static_cast<ptrdiff_t>(i));
                releaseSlot(s);
                had_screen = true;
            } else {
                ++i;
            }
        }
        if (had_screen) {
            sink_.onScreenStreamActive(type, false);
        }
        return;
    }

    // TEARDOWN carries only the stream type; release every audioType variant of it
    // (CarPlayMediaEngine.kt:531-542). The sink callbacks may re-enter and change audios_, so
    // the vector is re-examined from the current index after each one.
    for (size_t i = 0; i < audios_.size();) {
        if (audios_[i]->id.type == type) {
            AudioSlot* a = audios_[i];
            audios_.erase(audios_.begin() + static_cast<ptrdiff_t>(i));
            retireAudioSlot(a);
        } else {
            ++i;
        }
    }
}

void MediaEngine::onAudioDuck(session::Session& /*session*/, bool ducked) {
    ducked_ = ducked;
    sink_.onAudioDuck(ducked);
}

void MediaEngine::onSessionClosed(session::Session& /*session*/) {
    // A phone that disconnects during a prompt never sends unduckAudio.
    if (ducked_) {
        ducked_ = false;
        sink_.onAudioDuck(false);
    }
    closeAllStreams();
}

// May run while one of the slots is dispatching (a sink callback closed the session): every slot
// leaves its container BEFORE its sink notification, and releaseSlot() defers the delete of a
// dispatching slot.
void MediaEngine::closeAllStreams() {
    IapSlot* iap = iap_stream_;
    iap_stream_ = NULL;
    releaseSlot(iap);

    while (!screens_.empty()) {
        ScreenSlot* s = screens_.back();
        const int32_t stype = s->type;
        screens_.pop_back();
        releaseSlot(s);
        if (!shutting_down_) {
            sink_.onScreenStreamActive(stype, false);
        }
    }
    while (!audios_.empty()) {
        AudioSlot* a = audios_.back();
        audios_.pop_back();
        retireAudioSlot(a);
    }
    LockGuard lock(mic_mutex_);
    submitted_mic_pcm_.clear();
}

size_t MediaEngine::pushMicrophonePcm(const int16_t* samples, size_t sample_count) {
    if (samples == NULL || sample_count == 0) {
        return 0;
    }
    // The most recently set up stream whose microphone has started. Capture is only meant to
    // run between onMicrophoneStarted and onMicrophoneStopped; anything else is discarded.
    AudioSlot* target = NULL;
    for (size_t i = audios_.size(); i > 0; --i) {
        AudioSlot* s = audios_[i - 1];
        if (s->mic_started && s->mic_packetizer.configured() && s->data_sock.isOpen()) {
            target = s;
            break;
        }
    }
    if (target == NULL) {
        return 0;
    }
    std::vector<std::vector<uint8_t> > packets;
    target->mic_packetizer.push(samples, sample_count, packets);
    size_t sent_count = 0;
    for (size_t i = 0; i < packets.size(); ++i) {
        const std::vector<uint8_t>& pkt = packets[i];
        if (!pkt.empty() &&
            target->data_sock.sendTo(&pkt[0], pkt.size(), target->mic_dest) == kIoOk) {
            sent_count += 1;
        }
    }
    return sent_count;
}

bool MediaEngine::submitMicrophonePcm(const int16_t* samples, size_t sample_count) {
    if (samples == NULL || sample_count == 0) {
        return false;
    }
    // Queued worker samples are capped at ~1 second of 48 kHz stereo to bound memory when the
    // reactor thread is stalled.
    static const size_t kMaxQueuedSamples = 96000U;
    bool need_post = false;
    {
        LockGuard lock(mic_mutex_);
        if (sample_count > kMaxQueuedSamples ||
            submitted_mic_pcm_.size() > kMaxQueuedSamples - sample_count) {
            return false;
        }
        submitted_mic_pcm_.insert(submitted_mic_pcm_.end(), samples, samples + sample_count);
        if (!mic_post_pending_) {
            mic_post_pending_ = true;
            need_post = true;
        }
    }
    if (need_post && !reactor_.post(&MediaEngine::onMicWorkerPost, this)) {
        // Nothing will drain the queue: take the samples back out so that the next submit
        // starts clean and retries the post.
        LockGuard lock(mic_mutex_);
        mic_post_pending_ = false;
        submitted_mic_pcm_.clear();
        return false;
    }
    return true;
}

void MediaEngine::onMicWorkerPost(void* ctx) {
    MediaEngine* self = static_cast<MediaEngine*>(ctx);
    self->drainSubmittedMicPcm();
}

void MediaEngine::drainSubmittedMicPcm() {
    std::vector<int16_t> local;
    {
        LockGuard lock(mic_mutex_);
        local.swap(submitted_mic_pcm_);
        mic_post_pending_ = false;
    }
    if (!local.empty() && !shutting_down_) {
        pushMicrophonePcm(&local[0], local.size());
    }
}

bool MediaEngine::microphoneActive() const {
    for (size_t i = audios_.size(); i > 0; --i) {
        if (audios_[i - 1]->mic_started) {
            return true;
        }
    }
    return false;
}

const audio::MicStreamParams* MediaEngine::activeMicrophoneParams() const {
    for (size_t i = audios_.size(); i > 0; --i) {
        const AudioSlot* s = audios_[i - 1];
        if (s->mic_wanted) {
            return &s->mic_params;
        }
    }
    return NULL;
}

}  // namespace platform
}  // namespace carplay
