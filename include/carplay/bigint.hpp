#ifndef CARPLAY_BIGINT_HPP
#define CARPLAY_BIGINT_HPP

// Minimal fixed-width unsigned big-number arithmetic for SRP-6a (RFC 5054 3072-bit group).
//
// Design notes
// ------------
// * Pure C++11 (GCC 4.7 / -std=gnu++0x): 32-bit limbs with 64-bit intermediate products.
//   No __int128, intrinsics or inline assembly, so it builds unchanged for 32-bit ARMv7.
// * Every Number is a fixed array of kMaxLimbs (96) little-endian uint32_t limbs = 384 bytes.
//   No heap allocation is performed by any arithmetic routine.
// * Modular arithmetic goes through a Modulus context that precomputes Montgomery constants
//   (-N^-1 mod 2^32 and R^2 mod N with R = 2^(32 * limbCount)). Only ODD moduli > 1 are
//   supported (Montgomery requirement); init() rejects even moduli and 0/1.
// * modExp() uses CIOS Montgomery multiplication with a fixed 4-bit window
//   (16-entry precomputed table).
// * Stack footprint (worst case, 96 limbs): Montgomery multiply ~400 B; modExp ~7.5 KB
//   (16-entry table = 6 KB + accumulators); reduce() of a 512-byte input ~1.3 KB.
//   A Modulus object is ~1.2 KB.
//
// SECURITY NOTE: this code is NOT constant-time (variable-time window skipping of leading zero
// exponent nibbles, data-dependent final subtraction / comparisons). That is acceptable for the
// AirPlay/CarPlay pair-setup use case, where the SRP password is the fixed public setup code
// "3939"; do not reuse this module where timing side channels on secret exponents matter.
// Secret temporaries are still wiped with crypto::wipe.

#include <stddef.h>
#include <stdint.h>
#include <vector>

namespace carplay {
namespace bigint {

static const size_t kMaxBits = 3072;
static const size_t kMaxLimbs = kMaxBits / 32;   // 96
static const size_t kMaxBytes = kMaxBits / 8;    // 384
/// Maximum byte length accepted by Modulus::reduce(bytes) (values wider than the modulus).
static const size_t kMaxReduceInputBytes = 512;

/// Fixed-capacity unsigned integer < 2^3072. limbs[0] is the least significant limb.
struct Number {
    uint32_t limbs[kMaxLimbs];

    Number();                       // zero
    /// Securely zeroes all limbs.
    void clear();
};

/// Builds a Number from a 32-bit value.
Number fromUint32(uint32_t value);

/// Parses big-endian bytes (leading zero bytes allowed, any length). Returns false if the value
/// does not fit in 3072 bits; out is set to zero in that case.
bool fromBytesBE(const uint8_t* data, size_t len, Number& out);

/// Minimal big-endian encoding without leading zero bytes; zero encodes as a single 0x00 byte
/// (identical to Kotlin `Srp6a.toBytes`).
void toBytesBE(const Number& value, std::vector<uint8_t>& out);

/// Big-endian encoding left-padded with zeros to exactly `len` bytes.
/// Returns false (out cleared) if the minimal encoding does not fit in `len` bytes.
bool toBytesBEPadded(const Number& value, size_t len, std::vector<uint8_t>& out);

/// Returns -1, 0 or 1.
int compare(const Number& a, const Number& b);
bool isZero(const Number& a);
/// Number of significant bits (0 for zero).
size_t bitLength(const Number& a);

/// Odd-modulus Montgomery context. All arithmetic methods allow `out` to alias inputs.
class Modulus {
public:
    Modulus();

    /// Initialises the context. Returns false (context invalid) if n is even or n < 3.
    bool init(const Number& n);
    bool valid() const { return valid_; }
    const Number& value() const { return n_; }
    /// Number of 32-bit limbs spanned by the modulus.
    size_t limbCount() const { return nlimbs_; }

    /// out = value mod N for an arbitrary big-endian byte string of up to
    /// kMaxReduceInputBytes bytes (longer inputs are rejected even if they have leading zeros).
    bool reduce(const uint8_t* data, size_t len, Number& out) const;
    /// out = a mod N for any Number (a may be >= N).
    bool reduce(const Number& a, Number& out) const;

    /// out = (a + b) mod N. Requires a, b < N (returns false otherwise).
    bool addMod(const Number& a, const Number& b, Number& out) const;
    /// out = (a - b) mod N. Requires a, b < N.
    bool subMod(const Number& a, const Number& b, Number& out) const;
    /// out = (a * b) mod N. Requires a, b < N.
    bool mulMod(const Number& a, const Number& b, Number& out) const;
    /// out = base^exponent mod N. `base` may be any Number (reduced internally); the exponent is
    /// an arbitrary-length big-endian byte string (empty or all-zero exponent gives 1).
    bool modExp(const Number& base, const uint8_t* exponent, size_t exponent_len, Number& out) const;

private:
    void montMul(const uint32_t* a, const uint32_t* b, uint32_t* out) const;
    bool lessThanN(const Number& a) const;
    bool reduceLimbs(const uint32_t* limbs, size_t count, Number& out) const;

    Number n_;
    Number r2_;        // R^2 mod N
    Number one_mont_;  // R mod N (Montgomery form of 1)
    uint32_t n0inv_;   // -N^-1 mod 2^32
    size_t nlimbs_;
    bool valid_;
};

}  // namespace bigint
}  // namespace carplay

#endif  // CARPLAY_BIGINT_HPP
