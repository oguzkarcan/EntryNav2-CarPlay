#include "carplay/bigint.hpp"

#include "carplay/airplay_crypto.hpp"

#include <string.h>

namespace carplay {
namespace bigint {

namespace {

static const size_t kMaxReduceLimbs = kMaxReduceInputBytes / 4;  // 128

size_t significantLimbs(const uint32_t* limbs, size_t count) {
    while (count > 0 && limbs[count - 1] == 0) {
        --count;
    }
    return count;
}

// Big-endian bytes -> little-endian limbs. Caller guarantees capacity >= ceil(len / 4) after
// skipping leading zero bytes.
void bytesToLimbs(const uint8_t* data, size_t len, uint32_t* limbs, size_t capacity) {
    memset(limbs, 0, capacity * sizeof(uint32_t));
    for (size_t i = 0; i < len; ++i) {
        const size_t byte_index = len - 1 - i;  // position from the least-significant end
        limbs[byte_index / 4] |= static_cast<uint32_t>(data[i]) << ((byte_index % 4) * 8);
    }
}

// Strips leading zero bytes.
void stripLeadingZeros(const uint8_t*& data, size_t& len) {
    while (len > 0 && data[0] == 0) {
        ++data;
        --len;
    }
}

// r = a - b over n limbs; returns borrow.
uint32_t subLimbs(const uint32_t* a, const uint32_t* b, uint32_t* r, size_t n) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < n; ++i) {
        const uint64_t d = static_cast<uint64_t>(a[i]) - b[i] - borrow;
        r[i] = static_cast<uint32_t>(d);
        borrow = static_cast<uint32_t>((d >> 32) & 1U);
    }
    return borrow;
}

// r = a + b over n limbs; returns carry.
uint32_t addLimbs(const uint32_t* a, const uint32_t* b, uint32_t* r, size_t n) {
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        carry += static_cast<uint64_t>(a[i]) + b[i];
        r[i] = static_cast<uint32_t>(carry);
        carry >>= 32;
    }
    return static_cast<uint32_t>(carry);
}

// Compares a and b over n limbs.
int compareLimbs(const uint32_t* a, const uint32_t* b, size_t n) {
    for (size_t i = n; i > 0; --i) {
        if (a[i - 1] != b[i - 1]) {
            return a[i - 1] < b[i - 1] ? -1 : 1;
        }
    }
    return 0;
}

}  // namespace

Number::Number() {
    memset(limbs, 0, sizeof(limbs));
}

void Number::clear() {
    crypto::wipe(limbs, sizeof(limbs));
}

Number fromUint32(uint32_t value) {
    Number n;
    n.limbs[0] = value;
    return n;
}

bool fromBytesBE(const uint8_t* data, size_t len, Number& out) {
    out = Number();
    if (len > 0 && data == NULL) {
        return false;
    }
    stripLeadingZeros(data, len);
    if (len > kMaxBytes) {
        return false;
    }
    bytesToLimbs(data, len, out.limbs, kMaxLimbs);
    return true;
}

void toBytesBE(const Number& value, std::vector<uint8_t>& out) {
    out.clear();
    const size_t bits = bitLength(value);
    if (bits == 0) {
        out.push_back(0);
        return;
    }
    const size_t nbytes = (bits + 7) / 8;
    out.resize(nbytes);
    for (size_t i = 0; i < nbytes; ++i) {
        const size_t byte_index = nbytes - 1 - i;
        out[i] = static_cast<uint8_t>(value.limbs[byte_index / 4] >> ((byte_index % 4) * 8));
    }
}

bool toBytesBEPadded(const Number& value, size_t len, std::vector<uint8_t>& out) {
    out.clear();
    const size_t nbytes = (bitLength(value) + 7) / 8;
    if (nbytes > len) {
        return false;
    }
    out.assign(len, 0);
    for (size_t byte_index = 0; byte_index < nbytes; ++byte_index) {
        out[len - 1 - byte_index] =
            static_cast<uint8_t>(value.limbs[byte_index / 4] >> ((byte_index % 4) * 8));
    }
    return true;
}

int compare(const Number& a, const Number& b) {
    return compareLimbs(a.limbs, b.limbs, kMaxLimbs);
}

bool isZero(const Number& a) {
    return significantLimbs(a.limbs, kMaxLimbs) == 0;
}

size_t bitLength(const Number& a) {
    const size_t n = significantLimbs(a.limbs, kMaxLimbs);
    if (n == 0) {
        return 0;
    }
    uint32_t top = a.limbs[n - 1];
    size_t bits = 0;
    while (top != 0) {
        ++bits;
        top >>= 1;
    }
    return (n - 1) * 32 + bits;
}

// ---------------------------------------------------------------------------------------------
// Modulus
// ---------------------------------------------------------------------------------------------

Modulus::Modulus() : n0inv_(0), nlimbs_(0), valid_(false) {}

bool Modulus::init(const Number& n) {
    valid_ = false;
    n_ = n;
    r2_ = Number();
    one_mont_ = Number();
    nlimbs_ = significantLimbs(n.limbs, kMaxLimbs);
    if (nlimbs_ == 0 || (n.limbs[0] & 1U) == 0 || (nlimbs_ == 1 && n.limbs[0] < 3)) {
        nlimbs_ = 0;
        return false;
    }

    // Newton iteration for N0^-1 mod 2^32 (5 iterations double 1 -> 32 correct bits).
    const uint32_t n0 = n.limbs[0];
    uint32_t inv = 1;
    for (int i = 0; i < 5; ++i) {
        inv *= 2U - n0 * inv;
    }
    n0inv_ = static_cast<uint32_t>(0U - inv);

    // R^2 mod N by repeated modular doubling of 1 (2 * 32 * nlimbs doublings). One-time cost,
    // not in the exponentiation hot path.
    Number x = fromUint32(1);
    const size_t doublings = 64 * nlimbs_;
    for (size_t i = 0; i < doublings; ++i) {
        Number t;
        const uint32_t carry = addLimbs(x.limbs, x.limbs, t.limbs, nlimbs_);
        if (carry != 0 || compareLimbs(t.limbs, n_.limbs, nlimbs_) >= 0) {
            subLimbs(t.limbs, n_.limbs, t.limbs, nlimbs_);
        }
        x = t;
    }
    r2_ = x;
    valid_ = true;

    const Number one = fromUint32(1);
    montMul(one.limbs, r2_.limbs, one_mont_.limbs);  // 1 * R^2 / R = R mod N
    return true;
}

bool Modulus::lessThanN(const Number& a) const {
    return compare(a, n_) < 0;
}

// CIOS Montgomery multiplication: out = a * b * R^-1 mod N.
// Preconditions: b < N, a < R (= 2^(32 * nlimbs)). Output is fully reduced (< N) and
// limbs >= nlimbs are zeroed. `out` may alias a or b.
void Modulus::montMul(const uint32_t* a, const uint32_t* b, uint32_t* out) const {
    const size_t n = nlimbs_;
    uint32_t t[kMaxLimbs + 2];
    memset(t, 0, (n + 2) * sizeof(uint32_t));
    const uint32_t* nl = n_.limbs;

    for (size_t i = 0; i < n; ++i) {
        const uint64_t ai = a[i];
        uint64_t c = 0;
        for (size_t j = 0; j < n; ++j) {
            c += ai * b[j] + t[j];
            t[j] = static_cast<uint32_t>(c);
            c >>= 32;
        }
        c += t[n];
        t[n] = static_cast<uint32_t>(c);
        t[n + 1] = static_cast<uint32_t>(c >> 32);

        const uint64_t m = static_cast<uint32_t>(t[0] * n0inv_);
        c = m * nl[0] + t[0];
        c >>= 32;
        for (size_t j = 1; j < n; ++j) {
            c += m * nl[j] + t[j];
            t[j - 1] = static_cast<uint32_t>(c);
            c >>= 32;
        }
        c += t[n];
        t[n - 1] = static_cast<uint32_t>(c);
        c >>= 32;
        t[n] = t[n + 1] + static_cast<uint32_t>(c);
    }

    // t < 2N: one conditional subtraction.
    if (t[n] != 0 || compareLimbs(t, nl, n) >= 0) {
        subLimbs(t, nl, t, n);
    }
    memcpy(out, t, n * sizeof(uint32_t));
    if (n < kMaxLimbs) {
        memset(out + n, 0, (kMaxLimbs - n) * sizeof(uint32_t));
    }
    crypto::wipe(t, sizeof(t));
}

bool Modulus::reduceLimbs(const uint32_t* limbs, size_t count, Number& out) const {
    if (!valid_) {
        return false;
    }
    const size_t n = nlimbs_;
    count = significantLimbs(limbs, count);
    const Number one = fromUint32(1);
    Number r;
    Number chunk;
    // Horner over n-limb chunks from the most significant end: r = r * R + chunk (mod N).
    const size_t chunks = (count + n - 1) / n;
    for (size_t c = chunks; c > 0; --c) {
        const size_t lo = (c - 1) * n;
        const size_t take = (count - lo < n) ? (count - lo) : n;
        chunk = Number();
        memcpy(chunk.limbs, limbs + lo, take * sizeof(uint32_t));
        // chunk < R, r2 < N  =>  montMul(chunk, R^2) = chunk * R mod N; then * 1 / R => chunk mod N.
        montMul(chunk.limbs, r2_.limbs, chunk.limbs);
        montMul(chunk.limbs, one.limbs, chunk.limbs);
        // r * R mod N.
        montMul(r.limbs, r2_.limbs, r.limbs);
        const uint32_t carry = addLimbs(r.limbs, chunk.limbs, r.limbs, n);
        if (carry != 0 || compareLimbs(r.limbs, n_.limbs, n) >= 0) {
            subLimbs(r.limbs, n_.limbs, r.limbs, n);
        }
    }
    out = r;
    r.clear();
    chunk.clear();
    return true;
}

bool Modulus::reduce(const uint8_t* data, size_t len, Number& out) const {
    if (!valid_ || len > kMaxReduceInputBytes || (len > 0 && data == NULL)) {
        return false;
    }
    stripLeadingZeros(data, len);
    uint32_t limbs[kMaxReduceLimbs];
    bytesToLimbs(data, len, limbs, kMaxReduceLimbs);
    const bool ok = reduceLimbs(limbs, kMaxReduceLimbs, out);
    crypto::wipe(limbs, sizeof(limbs));
    return ok;
}

bool Modulus::reduce(const Number& a, Number& out) const {
    if (!valid_) {
        return false;
    }
    if (lessThanN(a)) {
        out = a;
        return true;
    }
    return reduceLimbs(a.limbs, kMaxLimbs, out);
}

bool Modulus::addMod(const Number& a, const Number& b, Number& out) const {
    if (!valid_ || !lessThanN(a) || !lessThanN(b)) {
        return false;
    }
    Number r;
    const uint32_t carry = addLimbs(a.limbs, b.limbs, r.limbs, nlimbs_);
    if (carry != 0 || compareLimbs(r.limbs, n_.limbs, nlimbs_) >= 0) {
        subLimbs(r.limbs, n_.limbs, r.limbs, nlimbs_);
    }
    out = r;
    r.clear();
    return true;
}

bool Modulus::subMod(const Number& a, const Number& b, Number& out) const {
    if (!valid_ || !lessThanN(a) || !lessThanN(b)) {
        return false;
    }
    Number r;
    const uint32_t borrow = subLimbs(a.limbs, b.limbs, r.limbs, nlimbs_);
    if (borrow != 0) {
        addLimbs(r.limbs, n_.limbs, r.limbs, nlimbs_);  // wraps back into [0, N)
    }
    out = r;
    r.clear();
    return true;
}

bool Modulus::mulMod(const Number& a, const Number& b, Number& out) const {
    if (!valid_ || !lessThanN(a) || !lessThanN(b)) {
        return false;
    }
    Number r;
    montMul(a.limbs, b.limbs, r.limbs);     // a*b/R
    montMul(r.limbs, r2_.limbs, r.limbs);   // a*b
    out = r;
    r.clear();
    return true;
}

bool Modulus::modExp(const Number& base, const uint8_t* exponent, size_t exponent_len,
                     Number& out) const {
    if (!valid_ || (exponent_len > 0 && exponent == NULL)) {
        return false;
    }
    stripLeadingZeros(exponent, exponent_len);
    if (exponent_len == 0) {
        out = fromUint32(1);  // N >= 3, so 1 is already reduced.
        return true;
    }

    Number b;
    if (!reduce(base, b)) {
        return false;
    }

    // Fixed 4-bit window table: table[i] = base^i in Montgomery form.
    Number table[16];
    table[0] = one_mont_;
    montMul(b.limbs, r2_.limbs, table[1].limbs);
    for (size_t i = 2; i < 16; ++i) {
        montMul(table[i - 1].limbs, table[1].limbs, table[i].limbs);
    }

    Number acc;
    bool started = false;
    for (size_t i = 0; i < exponent_len; ++i) {
        const uint8_t byte = exponent[i];
        for (int half = 1; half >= 0; --half) {
            const uint32_t nib = static_cast<uint32_t>(byte >> (half * 4)) & 0x0fU;
            if (!started) {
                if (nib == 0) {
                    continue;
                }
                acc = table[nib];
                started = true;
                continue;
            }
            for (int s = 0; s < 4; ++s) {
                montMul(acc.limbs, acc.limbs, acc.limbs);
            }
            if (nib != 0) {
                montMul(acc.limbs, table[nib].limbs, acc.limbs);
            }
        }
    }

    const Number one = fromUint32(1);
    montMul(acc.limbs, one.limbs, acc.limbs);  // leave Montgomery form
    out = acc;

    acc.clear();
    b.clear();
    for (size_t i = 0; i < 16; ++i) {
        table[i].clear();
    }
    return true;
}

}  // namespace bigint
}  // namespace carplay
