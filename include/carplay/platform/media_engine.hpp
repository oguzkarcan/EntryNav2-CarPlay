#ifndef CARPLAY_PLATFORM_MEDIA_ENGINE_HPP
#define CARPLAY_PLATFORM_MEDIA_ENGINE_HPP

// Reactor-driven AirPlay / CarPlay MediaHandler implementation:
//   * Screen TCP receiver (stream types 110 main, 111 alt/cluster):
//     - binds an ephemeral dual-stack TcpListener;
//     - accepts a single connection only from the active control peer's host address;
//     - parses 128-byte ScreenPacketHeader records, extracts avcC/hvcC config to Annex B,
//       decrypts ChaCha20-Poly1305 video frames and converts 4-byte length-prefixed NALs
//       in-place to Annex B before handing them to MediaSink;
//     - like ScreenStream.kt: a frame body shorter than the tag and unknown opcodes are skipped;
//       a decrypt failure, an oversized body, peer EOF or a socket error end the stream AND the
//       session.
//   * Realtime Audio UDP receivers (stream types 100 / 101 / 102):
//     - binds ephemeral data + control UDP sockets per (type, audioType) stream, requesting
//       a 512 KiB kernel receive buffer on the data socket;
//     - verifies sender host address, decrypts RTP packets with the stream's output key,
//       orders LPCM packets through audio::JitterBuffer, converts big-endian wire samples
//       to host int16, and delivers them to MediaSink.
//   * Microphone RTP uplink (type 100 when requested by the stream):
//     - starts at the first downlink audio packet or after mic_silent_start_ms for
//       non-telephony streams (e.g. Siri / voice notes with no downlink audio);
//     - accepts host-order int16 PCM on the reactor thread (pushMicrophonePcm) or from a
//       capture worker thread (submitMicrophonePcm), seals RTP packets with MicPacketizer,
//       and sends them to the phone's UDP dataPort; PCM handed over before the microphone
//       started (MediaSink::onMicrophoneStarted) is discarded.
//   * iAP2-over-CarPlay DataStream TCP receiver (stream type 130, UUID E9459FD0-...):
//     - binds an ephemeral dual-stack TcpListener with peer-host filtering;
//     - decrypts [u16 LE len | ciphertext | tag16] frames with the seed-derived output key,
//       parses 32-byte APTransportPackage headers, and forwards 'comm' payloads to MediaSink;
//     - like IapTunnel.kt: one connection at a time, peer EOF keeps the port listening for a
//       reconnect (read counter restarts at 0); a decrypt / framing failure or a socket error
//       ends the tunnel AND the session.
//   * POST /feedback responder reporting active audio streams' sampleRate, streamConnectionID,
//     synced NTP timestamp, raw monotonic ns, and estimated sampleTime.
//
// Threading and lifetime:
//   * Everything except submitMicrophonePcm() belongs to the reactor thread, the destructor
//     included. Stop the capture thread (no more submitMicrophonePcm calls) before destroying
//     the engine.
//   * MediaSink callbacks run synchronously from the stream's own socket / timer callback and
//     MAY re-enter the engine or the SessionServer, e.g. close the session from onVideoFrame()
//     or onIapMessage(). A stream released that way delivers nothing further; pointers handed
//     to the callback stay valid until it returns.
//   * Sockets come out of the Reactor's fixed table: 1 per screen / iAP stream, 2 per audio
//     stream.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/airplay_session.hpp"
#include "carplay/audio_rtp.hpp"
#include "carplay/mic_uplink.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/tcp.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/udp.hpp"
#include "carplay/screen_stream.hpp"

namespace carplay {
namespace platform {

/// Identity of one CarPlay audio stream: the numeric stream type (100/101/102) plus its
/// lowercased audioType ("media", "telephony", "speechrecognition", "default", ...).
struct AudioStreamId {
    int32_t type;
    std::string audio_type;

    AudioStreamId() : type(0), audio_type("default") {}
    AudioStreamId(int32_t t, const std::string& at) : type(t), audio_type(at) {}

    bool operator==(const AudioStreamId& o) const {
        return type == o.type && audio_type == o.audio_type;
    }
    bool operator!=(const AudioStreamId& o) const { return !(*this == o); }
    bool operator<(const AudioStreamId& o) const {
        if (type != o.type) return type < o.type;
        return audio_type < o.audio_type;
    }
};

/// Rendering and capture seam for decrypted CarPlay media streams.
/// All methods are invoked on the reactor thread and default to no-ops.
class MediaSink {
public:
    virtual ~MediaSink() {}

    /// Screen stream (110 main, 111 alt) opened on SETUP (true) or torn down / closed (false).
    virtual void onScreenStreamActive(int32_t /*type*/, bool /*active*/) {}

    /// Video decoder configuration (kOpVideoConfig = 1).
    /// For H.264 avcC configs, `annexb_data[0..annexb_len)` holds the extracted SPS/PPS in
    /// Annex-B start-code form (`00 00 00 01 | SPS | 00 00 00 01 | PPS`); `raw_config[0..raw_len)`
    /// holds the stripped avcC/hvcC record (or original body).
    virtual void onVideoConfig(int32_t /*type*/,
                               stream::VideoCodecType /*codec*/,
                               const uint8_t* /*annexb_data*/,
                               size_t /*annexb_len*/,
                               const uint8_t* /*raw_config*/,
                               size_t /*raw_len*/,
                               float /*width_px*/,
                               float /*height_px*/) {}

    /// Decrypted video frame (kOpVideoFrame = 0) converted to Annex-B start codes.
    virtual void onVideoFrame(int32_t /*type*/,
                              const uint8_t* /*annexb_data*/,
                              size_t /*len*/,
                              uint64_t /*sender_nanos*/,
                              int64_t /*arrival_mono_nanos*/) {}

    /// First valid decrypted RTP audio packet arrived on stream `id`.
    virtual void onAudioStarted(const AudioStreamId& /*id*/,
                                const audio::AudioFormat& /*format*/,
                                uint32_t /*first_sample*/) {}

    /// Decrypted raw RTP packet (before JitterBuffer / LPCM conversion).
    virtual void onAudioRtp(const AudioStreamId& /*id*/,
                            const audio::AudioFormat& /*format*/,
                            const audio::RtpHeader& /*header*/,
                            const uint8_t* /*payload*/,
                            size_t /*payload_len*/) {}

    /// In-order LPCM audio frame popped from the stream's JitterBuffer in host-order int16.
    virtual void onAudioPcm(const AudioStreamId& /*id*/,
                            const audio::AudioFormat& /*format*/,
                            const int16_t* /*samples*/,
                            size_t /*sample_count*/,
                            uint16_t /*sequence*/,
                            uint32_t /*rtp_timestamp*/) {}

    /// Missing RTP sequence declared lost by the stream's JitterBuffer.
    virtual void onAudioPacketLost(const AudioStreamId& /*id*/,
                                   const audio::AudioFormat& /*format*/,
                                   uint16_t /*lost_sequence*/) {}

    /// Audio stream torn down or replaced.
    virtual void onAudioStopped(const AudioStreamId& /*id*/) {}

    /// Inbound POST /command duckAudio (true) or unduckAudio / session close while ducked (false).
    virtual void onAudioDuck(bool /*ducked*/) {}

    /// Microphone capture requested and ready to transmit to `peer_dest`.
    virtual void onMicrophoneStarted(const AudioStreamId& /*id*/,
                                     const audio::MicStreamParams& /*params*/,
                                     const Address& /*peer_dest*/) {}

    /// Microphone stream torn down or replaced.
    virtual void onMicrophoneStopped(const AudioStreamId& /*id*/) {}

    /// Inbound iAP2 payload received on the type-130 DataStream tunnel.
    virtual void onIapMessage(const uint8_t* /*data*/, size_t /*len*/) {}
};

struct MediaEngineConfig {
    /// Whether type-100 streams requesting input may open a microphone uplink.
    bool microphone_enabled;
    /// Delay (ms) before starting a non-telephony microphone when no downlink RTP packet has
    /// arrived yet (MicrophoneStart.SILENT_START_MILLIS = 500). 0 = start immediately on SETUP;
    /// < 0 = wait solely for downlink audio.
    int64_t mic_silent_start_ms;
    /// Per-stream JitterBuffer capacity and reorder depth for LPCM downlink audio.
    size_t audio_jitter_capacity;
    uint16_t audio_jitter_reorder_depth;
    /// Upper bound on concurrently open audio streams (each takes two reactor sockets). The
    /// stream id is (type, audioType) with a peer-chosen audioType string, so without a bound a
    /// verified peer could fill the reactor's socket table. A SETUP beyond the bound is declined;
    /// replacing an existing (type, audioType) is always possible.
    size_t max_audio_streams;
    /// Maximum allowed ScreenPacketHeader::payload_size (8 MiB in reference ScreenStream).
    size_t max_screen_payload_bytes;
    /// Maximum allowed APTransportPackage size on the iAP2 DataStream (4 MiB in reference).
    size_t max_iap_package_bytes;
    /// When true (default), screen TCP accepts, iAP2 TCP accepts, and audio UDP packets must
    /// originate from the active control connection's host address.
    bool enforce_peer_address;
    /// When true (wireless Wi-Fi AP sessions), mark screen TCP and audio UDP sockets with
    /// IP_TOS / IPV6_TCLASS = 0x80 (WMM AC_VI) as BMW's native CarPlay SocketSetQoS does.
    /// Leave false for wired USB (NCM/TAP) sessions.
    bool wifi_video_qos;

    MediaEngineConfig()
        : microphone_enabled(true),
          mic_silent_start_ms(500),
          audio_jitter_capacity(audio::JitterBuffer::kDefaultCapacity),
          audio_jitter_reorder_depth(audio::JitterBuffer::kDefaultReorderDepth),
          max_audio_streams(16),
          max_screen_payload_bytes(8U * 1024U * 1024U),
          max_iap_package_bytes(4U * 1024U * 1024U),
          enforce_peer_address(true),
          wifi_video_qos(false) {}
};

class MediaEngine : public session::MediaHandler {
public:
    typedef uint64_t (*SyncedNtpFn)(void* ctx);
    typedef void (*SessionActionFn)(void* ctx);

    MediaEngine(Reactor& reactor,
                MediaSink& sink,
                const MediaEngineConfig& config = MediaEngineConfig());
    virtual ~MediaEngine();

    /// Sets the peer address of the active control connection (used for TCP accept filters,
    /// UDP sender checks, and the destination IP of microphone RTP packets).
    void setControlPeer(const Address& peer);
    const Address& controlPeer() const { return control_peer_; }

    /// Enables or disables Wi-Fi video QoS (IP_TOS / IPV6_TCLASS = 0x80) for subsequent
    /// Screen TCP accepts and Audio UDP sockets (true for wireless, false for wired USB).
    void setWifiVideoQos(bool enabled) { config_.wifi_video_qos = enabled; }
    bool wifiVideoQos() const { return config_.wifi_video_qos; }

    /// Optional callback returning the session's current synchronized 64-bit NTP timestamp
    /// for POST /feedback responses. When unset, ntp::ntpFromNanos(reactor.now()) is used.
    void setSyncedNtpCallback(SyncedNtpFn fn, void* ctx);

    /// Optional callback invoked when a screen stream ends (peer EOF included) or the iAP2 tunnel
    /// fails and the owning CarPlay session must close (ScreenStream.kt / IapTunnel.kt onClosed).
    void setCloseSessionCallback(SessionActionFn fn, void* ctx);

    /// Forgets the two callbacks above if they were registered with `ctx` (their owner is going
    /// away). Callbacks registered by someone else are left alone.
    void clearSessionCallbacks(void* ctx);
    bool hasSessionCallbacks() const { return synced_ntp_fn_ != NULL || close_session_fn_ != NULL; }

    // ---- session::MediaHandler implementation ----
    virtual bool onScreen(session::Session& session,
                          int32_t type,
                          const bplist::Value& stream,
                          int32_t& data_port_out);
    virtual bool onAudio(session::Session& session,
                         int32_t type,
                         const bplist::Value& stream,
                         bplist::Value& response_out);
    virtual bool onDataStream(session::Session& session,
                              const bplist::Value& stream,
                              bplist::Value& response_out);
    virtual bool onFeedback(session::Session& session, bplist::Value& response_out);
    virtual void onTeardown(session::Session& session, int32_t type);
    virtual void onAudioDuck(session::Session& session, bool ducked);
    virtual void onSessionClosed(session::Session& session);

    // ---- Microphone uplink ----

    /// Reactor-thread only: pushes interleaved host-order int16 PCM samples into the packetizer
    /// of the most recently set up STARTED microphone and sends each completed RTP frame over UDP
    /// to the phone. Returns the number of UDP RTP packets transmitted (0 if only buffered, or if
    /// no microphone has started: such samples are discarded).
    size_t pushMicrophonePcm(const int16_t* samples, size_t sample_count);

    /// Thread-safe: queues captured PCM samples from an audio worker thread and wakes the
    /// reactor to packetize and transmit them. false when nothing was queued: NULL / empty
    /// input, the queue (about 1 s of 48 kHz stereo) is full, or the reactor refused the wake-up.
    bool submitMicrophonePcm(const int16_t* samples, size_t sample_count);

    /// A microphone has started (onMicrophoneStarted was delivered and not yet stopped).
    bool microphoneActive() const;
    /// Parameters of the most recently set up stream that wants a microphone, started or not.
    const audio::MicStreamParams* activeMicrophoneParams() const;

    // ---- Diagnostics / inspection ----
    size_t activeScreenCount() const { return screens_.size(); }
    size_t activeAudioCount() const { return audios_.size(); }
    bool hasDataStream() const { return iap_stream_ != NULL; }
    bool isDucked() const { return ducked_; }
    uint64_t audioAuthFailures() const { return audio_auth_failures_; }
    uint64_t audioStrangerDrops() const { return audio_stranger_drops_; }
    uint64_t screenRejectedPeers() const { return screen_rejected_peers_; }
    SocketHandle firstScreenSocketHandle() const;
    SocketHandle firstAudioDataSocketHandle() const;

private:
    MediaEngine(const MediaEngine&) = delete;
    MediaEngine& operator=(const MediaEngine&) = delete;

    struct ScreenSlot;
    struct AudioSlot;
    struct IapSlot;

    static void onMicWorkerPost(void* ctx);
    void drainSubmittedMicPcm();
    void closeAllStreams();
    /// Releases an audio slot that is no longer in audios_ and reports it stopped to the sink.
    void retireAudioSlot(AudioSlot* slot);
    bool peerAllowed(const Address& from) const;
    uint64_t currentSyncedNtp() const;
    void requestSessionClose();

    Reactor& reactor_;
    MediaSink& sink_;
    MediaEngineConfig config_;
    Address control_peer_;
    SyncedNtpFn synced_ntp_fn_;
    void* synced_ntp_ctx_;
    SessionActionFn close_session_fn_;
    void* close_session_ctx_;

    std::vector<ScreenSlot*> screens_;
    std::vector<AudioSlot*> audios_;
    IapSlot* iap_stream_;
    bool ducked_;
    bool shutting_down_;

    uint64_t audio_auth_failures_;
    uint64_t audio_stranger_drops_;
    uint64_t screen_rejected_peers_;

    Mutex mic_mutex_;
    std::vector<int16_t> submitted_mic_pcm_;
    bool mic_post_pending_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_MEDIA_ENGINE_HPP
