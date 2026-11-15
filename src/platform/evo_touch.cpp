#include "carplay/platform/evo_touch.hpp"

#include <string.h>

#ifdef __linux__
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#endif

#ifndef _WIN32
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "carplay/platform/log.hpp"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

namespace carplay {
namespace platform {

namespace {

int clampRound(double v, int lo, int hi) {
    const int i = static_cast<int>(v < 0.0 ? v - 0.5 : v + 0.5);
    if (i < lo) return lo;
    if (i > hi) return hi;
    return i;
}

uint32_t monoMs32() {
    return static_cast<uint32_t>(monotonicMillis());
}

}  // namespace

bool parseIpv4Udp(const uint8_t* p, size_t n, UdpView& out) {
    if (p == NULL || n < 20U || (p[0] >> 4) != 4U) {
        return false;
    }
    const size_t ihl = static_cast<size_t>(p[0] & 0x0FU) * 4U;
    const size_t total = (static_cast<size_t>(p[2]) << 8) | static_cast<size_t>(p[3]);
    if (ihl < 20U || total < ihl + 8U || total > n || p[9] != 17U) {
        return false;
    }
    if (((static_cast<unsigned>(p[6]) << 8) | static_cast<unsigned>(p[7])) & 0x3FFFU) {
        return false;  // MF flag or non-zero fragment offset
    }
    const uint8_t* u = p + ihl;
    const size_t ulen = (static_cast<size_t>(u[4]) << 8) | static_cast<size_t>(u[5]);
    if (ulen < 8U || ihl + ulen > total) {
        return false;
    }
    out.src = (static_cast<uint32_t>(p[12]) << 24) |
              (static_cast<uint32_t>(p[13]) << 16) |
              (static_cast<uint32_t>(p[14]) << 8) |
              static_cast<uint32_t>(p[15]);
    out.sport = static_cast<uint16_t>((static_cast<uint16_t>(u[0]) << 8) | u[1]);
    out.dport = static_cast<uint16_t>((static_cast<uint16_t>(u[2]) << 8) | u[3]);
    out.data = u + 8;
    out.len = ulen - 8U;
    return true;
}

bool isTouchPdu(const uint8_t* b, size_t n) {
    return b != NULL && n >= 4U && touchpdu::isIdent(b);
}

TouchTracker::TouchTracker(double sx, double sy, double ox, double oy, int max_x, int max_y)
    : sx_(sx),
      sy_(sy),
      ox_(ox),
      oy_(oy),
      max_x_(max_x),
      max_y_(max_y),
      picture_started_(true) {
    reset();
}

void TouchTracker::reset() {
    for (int j = 0; j < NS; ++j) {
        active_[j] = false;
        need_down_[j] = false;
        blocked_[j] = false;
        cx_[j] = 0;
        cy_[j] = 0;
    }
    reasm_.reset();
    have_msg_ = false;
    prev_seq0_ = 0U;
    prev_seq1_ = 0U;
    messages_ = 0U;
    last_n_ = 0;
}

int TouchTracker::activeCount() const {
    int n = 0;
    for (int j = 0; j < NS; ++j) {
        if (active_[j]) {
            ++n;
        }
    }
    return n;
}

int TouchTracker::lastContacts(RawTouchContact* out, int max) const {
    int n = 0;
    for (; n < last_n_ && n < max; ++n) {
        if (out != NULL) {
            out[n] = last_[n];
        }
    }
    return n;
}

void TouchTracker::fillActive(TouchEventOut& e, int which) const {
    e.n = 0;
    e.index = 0;
    e.action = TouchEventOut::kMove;
    for (int j = 0; j < NS && e.n < NS; ++j) {
        if (active_[j]) {
            if (j == which) {
                e.index = e.n;
            }
            e.p[e.n].id = j;
            e.p[e.n].x = cx_[j];
            e.p[e.n].y = cy_[j];
            ++e.n;
        }
    }
}

void TouchTracker::emitUp(TouchEventOut& e, int k, int x, int y) {
    cx_[k] = x;
    cy_[k] = y;
    const int cnt = activeCount();
    fillActive(e, k);
    e.action = (cnt <= 1) ? TouchEventOut::kRelease : TouchEventOut::kPointerUp;
    active_[k] = false;
}

int TouchTracker::releaseAll(TouchEventOut* evs, int max) {
    int ne = 0;
    for (int k = 0; k < NS && ne < max; ++k) {
        if (active_[k]) {
            emitUp(evs[ne++], k, cx_[k], cy_[k]);
            need_down_[k] = true;
        }
    }
    return ne;
}

int TouchTracker::feed(const uint8_t* buf, size_t n, TouchEventOut* evs, int max) {
    if (!isTouchPdu(buf, n)) {
        return -1;
    }
    TouchMsg msgs[kTouchMaxMsgs];
    const int nm = reasm_.feed(buf, n, msgs, kTouchMaxMsgs);
    if (nm < 0) {
        return -1;
    }
    int ne = 0;
    for (int mi = 0; mi < nm; ++mi) {
        if (have_msg_ && msgs[mi].seq0 == prev_seq0_) {
            continue;
        }
        const bool contiguous =
            have_msg_ && msgs[mi].seq0 == static_cast<uint8_t>(prev_seq1_ + 1U);
        have_msg_ = true;
        prev_seq0_ = msgs[mi].seq0;
        prev_seq1_ = msgs[mi].seq1;

        RawTouchContact c[NS];
        int declared = 0;
        const int nc = parseTouchStream(msgs[mi], c, NS, &declared);
        if (nc < 0) {
            continue;
        }
        ++messages_;
        last_n_ = nc;
        for (int k = 0; k < nc; ++k) {
            last_[k] = c[k];
        }

        int nx[NS];
        int ny[NS];
        int st[NS];
        bool seen[NS];
        for (int j = 0; j < NS; ++j) {
            st[j] = 0;
            seen[j] = false;
            nx[j] = cx_[j];
            ny[j] = cy_[j];
        }
        for (int k = 0; k < nc; ++k) {
            const int id = c[k].id;
            seen[id] = true;
            st[id] = c[k].state;
            nx[id] = clampRound(c[k].x * sx_ + ox_, 0, max_x_);
            ny[id] = clampRound(c[k].y * sy_ + oy_, 0, max_y_);
        }

        // Reject touches started before the picture until they lift.
        for (int k = 0; k < NS; ++k) {
            if (!seen[k] || st[k] == 3) {
                blocked_[k] = false;
            } else if (blocked_[k] || !picture_started_) {
                blocked_[k] = true;
                seen[k] = false;
            }
        }

        // Repeated "down" with contiguous sequence is a move on an active finger.
        for (int k = 0; k < NS; ++k) {
            if (seen[k] && st[k] == 1 && active_[k] && contiguous) {
                st[k] = 2;
            }
            if (seen[k] && st[k] != 2) {
                need_down_[k] = false;
            }
        }

        // Lifted/missing fingers, or fresh down on an already active slot: release first.
        for (int k = 0; k < NS && ne < max; ++k) {
            if (active_[k] && (!seen[k] || st[k] == 1)) {
                emitUp(evs[ne++], k, cx_[k], cy_[k]);
                if (!seen[k]) {
                    need_down_[k] = true;
                }
            }
        }

        // New downs.
        for (int k = 0; k < NS && ne < max; ++k) {
            if (seen[k] && st[k] == 2 && !active_[k] && need_down_[k] && contiguous) {
                continue;
            }
            if (seen[k] && (st[k] == 1 || (st[k] == 2 && !active_[k]))) {
                const int before = activeCount();
                active_[k] = true;
                need_down_[k] = false;
                cx_[k] = nx[k];
                cy_[k] = ny[k];
                TouchEventOut& e = evs[ne++];
                fillActive(e, k);
                e.action = (before == 0) ? TouchEventOut::kPress : TouchEventOut::kPointerDown;
            }
        }

        // Moves.
        bool moved = false;
        for (int k = 0; k < NS; ++k) {
            if (seen[k] && st[k] == 2 && active_[k] && (nx[k] != cx_[k] || ny[k] != cy_[k])) {
                cx_[k] = nx[k];
                cy_[k] = ny[k];
                moved = true;
            }
        }
        if (moved && ne < max) {
            fillActive(evs[ne], -1);
            evs[ne++].action = TouchEventOut::kMove;
        }

        // Explicit ups.
        for (int k = 0; k < NS && ne < max; ++k) {
            if (seen[k] && st[k] == 3 && active_[k]) {
                emitUp(evs[ne++], k, nx[k], ny[k]);
            }
        }
    }
    return ne;
}

EvoTouch::EvoTouch()
    : mode_(kInputOff),
      cb_(NULL),
      user_(NULL),
      running_(false),
      owned_(false),
      picture_started_(true),
      started_(false),
      udp_test_mode_(false),
      tap_(-1),
      steal_(-1),
      ifindex_(0),
      peer_ip_(0U),
      peer_port_(0U),
      have_peer_(false),
      steal_refused_(false),
      last_frame_ms_(0U),
      tracker_(1.0, 1.0, 0.0, 0.0, 1279, 719),
      tapped_(0U),
      touch_pdus_(0U),
      other_pdus_(0U),
      events_(0U),
      sent_(0U),
      stolen_(0U),
      finger_sent_(false) {}

EvoTouch::~EvoTouch() {
    stop();
}

void EvoTouch::setDisplaySize(uint32_t width_pixels, uint32_t height_pixels) {
    tracker_.setDisplaySize(width_pixels, height_pixels);
}

void EvoTouch::setScaleOffset(double sx, double sy, double ox, double oy) {
    tracker_.setScaleOffset(sx, sy, ox, oy);
}

void EvoTouch::setOwned(bool owned) {
    LockGuard lock(state_mutex_);
    owned_ = owned;
}

bool EvoTouch::owned() const {
    LockGuard lock(state_mutex_);
    return owned_;
}

void EvoTouch::setPictureStarted(bool started) {
    LockGuard lock(state_mutex_);
    picture_started_ = started;
}

bool EvoTouch::pictureStarted() const {
    LockGuard lock(state_mutex_);
    return picture_started_;
}

uint16_t EvoTouch::boundUdpPort() const {
    return udp_sock_.isOpen() ? udp_sock_.port() : 0U;
}

void EvoTouch::setCallback(Callback cb, void* user) {
    LockGuard lock(state_mutex_);
    cb_ = cb;
    user_ = user;
}

void EvoTouch::attachForTest(InputMode mode, Callback cb, void* user) {
    LockGuard lock(state_mutex_);
    mode_ = mode;
    if (cb != NULL) {
        cb_ = cb;
        user_ = user;
    }
}

bool EvoTouch::openTap() {
#ifdef __linux__
#ifdef SOCK_CLOEXEC
    tap_ = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
#else
    tap_ = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
#endif
    if (tap_ < 0) {
        CARPLAY_LOG_WARN("touch", "cannot open AF_PACKET tap: %s", strerror(errno));
        return false;
    }
    struct sock_filter code[] = {
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 9},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 6, 17},
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 6},
        {BPF_JMP | BPF_JSET | BPF_K, 4, 0, 0x3FFF},
        {BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0},
        {BPF_LD | BPF_H | BPF_IND, 0, 0, 2},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, kTouchPort},
        {BPF_RET | BPF_K, 0, 0, 0xFFFF},
        {BPF_RET | BPF_K, 0, 0, 0},
    };
    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(sizeof(code) / sizeof(code[0]));
    prog.filter = code;
    if (setsockopt(tap_, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) != 0) {
        CARPLAY_LOG_WARN("touch", "BPF filter refused: %s", strerror(errno));
        close(tap_);
        tap_ = -1;
        return false;
    }
    uint8_t junk[64];
    while (recv(tap_, junk, sizeof(junk), MSG_DONTWAIT) > 0) {
    }
    return true;
#else
    return false;
#endif
}

void EvoTouch::updateSteal(bool want) {
#ifdef __linux__
    if (!want && steal_ >= 0) {
        close(steal_);
        steal_ = -1;
    }
    if (!want || steal_ >= 0 || steal_refused_) {
        return;
    }
#ifdef SOCK_CLOEXEC
    const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#else
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (s < 0) {
        steal_refused_ = true;
        return;
    }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(kTouchPort);
    if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        close(s);
        steal_refused_ = true;
        return;
    }
    sockaddr_in p;
    memset(&p, 0, sizeof(p));
    p.sin_family = AF_INET;
    p.sin_addr.s_addr = htonl(peer_ip_);
    p.sin_port = htons(peer_port_);
    if (connect(s, reinterpret_cast<sockaddr*>(&p), sizeof(p)) != 0) {
        close(s);
        steal_refused_ = true;
        return;
    }
    steal_ = s;
#else
    (void)want;
#endif
}

bool EvoTouch::start(InputMode mode, Callback cb, void* user) {
    if (started_ || mode == kInputOff) {
        return mode == kInputOff;
    }
    mode_ = mode;
    if (cb != NULL) {
        LockGuard lock(state_mutex_);
        cb_ = cb;
        user_ = user;
    }
    udp_test_mode_ = false;
    if (!openTap()) {
        return false;
    }
    {
        LockGuard lock(state_mutex_);
        running_ = true;
    }
    if (!thread_.start(&EvoTouch::threadEntry, this)) {
        LockGuard lock(state_mutex_);
        running_ = false;
#ifndef _WIN32
        if (tap_ >= 0) {
            close(tap_);
            tap_ = -1;
        }
#endif
        return false;
    }
    started_ = true;
    return true;
}

bool EvoTouch::startUdpForTest(uint16_t bind_udp_port, InputMode mode, Callback cb, void* user) {
    if (started_ || mode == kInputOff) {
        return mode == kInputOff;
    }
    if (!udp_sock_.open(Address::ipv4Loopback(bind_udp_port))) {
        return false;
    }
    mode_ = mode;
    if (cb != NULL) {
        LockGuard lock(state_mutex_);
        cb_ = cb;
        user_ = user;
    }
    udp_test_mode_ = true;
    {
        LockGuard lock(state_mutex_);
        running_ = true;
    }
    if (!thread_.start(&EvoTouch::threadEntry, this)) {
        LockGuard lock(state_mutex_);
        running_ = false;
        udp_sock_.close();
        udp_test_mode_ = false;
        return false;
    }
    started_ = true;
    return true;
}

void EvoTouch::stop() {
    if (!started_) {
        return;
    }
    {
        LockGuard lock(state_mutex_);
        running_ = false;
    }
    thread_.join();
    started_ = false;
    udp_sock_.close();
    udp_test_mode_ = false;
#ifndef _WIN32
    if (steal_ >= 0) {
        close(steal_);
        steal_ = -1;
    }
    if (tap_ >= 0) {
        close(tap_);
        tap_ = -1;
    }
#endif
}

void EvoTouch::threadEntry(void* self) {
    static_cast<EvoTouch*>(self)->run();
}

void EvoTouch::emit(const TouchEventOut* ev, int n) {
    Callback cb = NULL;
    void* user = NULL;
    bool is_owned = false;
    {
        LockGuard lock(state_mutex_);
        cb = cb_;
        user = user_;
        is_owned = owned_;
    }
    const bool send = (mode_ == kInputForward && is_owned && cb != NULL);
    for (int i = 0; i < n; ++i) {
        ++events_;
        if (send) {
            cb(ev[i], user);
            ++sent_;
        }
    }
    if (send) {
        finger_sent_ = (tracker_.activeCount() > 0);
    }
}

void EvoTouch::releaseOnLostOwnership() {
    if (mode_ == kInputForward && !owned() && tracker_.activeCount() > 0) {
        Callback cb = NULL;
        void* user = NULL;
        {
            LockGuard lock(state_mutex_);
            cb = cb_;
            user = user_;
        }
        TouchEventOut ev[TouchTracker::NS];
        const int n = tracker_.releaseAll(ev, TouchTracker::NS);
        for (int i = 0; i < n; ++i) {
            ++events_;
            if (finger_sent_ && cb != NULL) {
                cb(ev[i], user);
                ++sent_;
            }
        }
        finger_sent_ = false;
    }
}

int EvoTouch::handle(const UdpView& u, uint32_t now_ms) {
    if (u.dport != kTouchPort) {
        return 0;
    }
    if (!isTouchPdu(u.data, u.len)) {
        ++other_pdus_;
        return 0;
    }
    if (!have_peer_) {
        have_peer_ = true;
        peer_ip_ = u.src;
        peer_port_ = u.sport;
    } else if (u.src != peer_ip_ || u.sport != peer_port_) {
        ++other_pdus_;
        return 0;
    }
    ++touch_pdus_;
    last_frame_ms_ = now_ms;
    TouchEventOut ev[16];
    tracker_.setPictureStarted(pictureStarted());
    const int n = tracker_.feed(u.data, u.len, ev, 16);
    if (n > 0) {
        emit(ev, n);
    }
    return n;
}

int EvoTouch::feedUdpPayload(const uint8_t* payload,
                             size_t len,
                             uint32_t src_ip,
                             uint16_t src_port,
                             uint32_t now_ms) {
    UdpView u;
    u.src = src_ip;
    u.sport = src_port;
    u.dport = kTouchPort;
    u.data = payload;
    u.len = len;
    return handle(u, now_ms);
}

void EvoTouch::checkTimeoutForTest(uint32_t now_ms) {
    releaseOnLostOwnership();
    if (tracker_.activeCount() > 0 &&
        static_cast<uint32_t>(now_ms - last_frame_ms_) >= kTouchTimeoutReleaseMs) {
        TouchEventOut ev[TouchTracker::NS];
        const int n = tracker_.releaseAll(ev, TouchTracker::NS);
        emit(ev, n);
    }
}

void EvoTouch::run() {
    uint8_t buf[2048];
    PollSet poll_set;
    poll_set.reserve(3U);

    for (;;) {
        {
            LockGuard lock(state_mutex_);
            if (!running_) {
                break;
            }
        }
        const bool own = owned();
        if (!udp_test_mode_ && mode_ == kInputForward) {
            updateSteal(own && have_peer_);
        }
        releaseOnLostOwnership();

        PollItem items[3];
        size_t count = 0U;
        size_t tap_idx = 99U;
        size_t steal_idx = 99U;
        size_t udp_idx = 99U;

        if (udp_test_mode_ && udp_sock_.isOpen()) {
            udp_idx = count;
            items[count].handle = udp_sock_.handle();
            items[count].events = kPollIn;
            items[count].revents = 0U;
            ++count;
        }
#ifdef __linux__
        if (!udp_test_mode_ && tap_ >= 0) {
            tap_idx = count;
            items[count].handle = tap_;
            items[count].events = kPollIn;
            items[count].revents = 0U;
            ++count;
        }
        if (!udp_test_mode_ && steal_ >= 0) {
            steal_idx = count;
            items[count].handle = steal_;
            items[count].events = kPollIn;
            items[count].revents = 0U;
            ++count;
        }
#else
        (void)tap_idx;
        (void)steal_idx;
#endif

        const int r = poll_set.wait(items, count, 50);
        const uint32_t now = monoMs32();
        if (r < 0) {
            continue;
        }

        if (udp_idx < count && (items[udp_idx].revents & kPollIn) != 0U) {
            for (int burst = 0; burst < 64; ++burst) {
                size_t got = 0U;
                Address from;
                const IoStatus st = udp_sock_.receiveFrom(buf, sizeof(buf), got, from);
                if (st != kIoOk && st != kIoTruncated) {
                    break;
                }
                UdpView u;
                if (from.family() == Address::kIPv4 && from.byteLength() == 4U) {
                    const uint8_t* b = from.bytes();
                    u.src = (static_cast<uint32_t>(b[0]) << 24) |
                            (static_cast<uint32_t>(b[1]) << 16) |
                            (static_cast<uint32_t>(b[2]) << 8) |
                            static_cast<uint32_t>(b[3]);
                } else {
                    u.src = 0x7F000001U;
                }
                u.sport = from.port();
                u.dport = kTouchPort;
                u.data = buf;
                u.len = got;
                ++tapped_;
                handle(u, now);
            }
        }

#ifdef __linux__
        if (tap_idx < count && (items[tap_idx].revents & kPollIn) != 0U) {
            for (int burst = 0; burst < 64; ++burst) {
                sockaddr_ll ll;
                socklen_t sl = sizeof(ll);
                memset(&ll, 0, sizeof(ll));
                const ssize_t got = recvfrom(tap_,
                                             buf,
                                             sizeof(buf),
                                             MSG_DONTWAIT,
                                             reinterpret_cast<sockaddr*>(&ll),
                                             &sl);
                if (got <= 0) {
                    break;
                }
                if (ll.sll_pkttype != PACKET_HOST) {
                    continue;
                }
                if (ifindex_ == 0) {
                    ifindex_ = ll.sll_ifindex;
                }
                if (ll.sll_ifindex != ifindex_) {
                    continue;
                }
                UdpView u;
                if (!parseIpv4Udp(buf, static_cast<size_t>(got), u)) {
                    continue;
                }
                ++tapped_;
                handle(u, now);
            }
        }
        if (steal_idx < count && (items[steal_idx].revents & kPollIn) != 0U) {
            while (recv(steal_, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
                ++stolen_;
            }
        }
#endif

        if (tracker_.activeCount() > 0 &&
            static_cast<uint32_t>(now - last_frame_ms_) >= kTouchTimeoutReleaseMs) {
            TouchEventOut ev[TouchTracker::NS];
            const int n = tracker_.releaseAll(ev, TouchTracker::NS);
            emit(ev, n);
        }
    }
}

}  // namespace platform
}  // namespace carplay
