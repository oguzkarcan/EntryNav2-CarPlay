// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_elf.hpp, PolyForm Noncommercial License 1.0.0

#include "carplay/platform/elf_symbols.hpp"

#include <stdio.h>
#include <string.h>

namespace carplay {
namespace platform {

namespace {

static const uint8_t kElfMagic[4] = {0x7fU, 'E', 'L', 'F'};
static const uint8_t kElfClass32 = 1U;
static const uint8_t kElfData2Lsb = 1U;
static const uint16_t kEmArm = 40U;

static const size_t kElf32EhdrSize = 52U;
static const size_t kElf32ShdrSize = 40U;
static const size_t kElf32SymSize = 16U;
static const size_t kElf32RelSize = 8U;

static const uint32_t kShtStrtab = 3U;
static const uint32_t kShtRel = 9U;
static const uint32_t kShtDynsym = 11U;
static const uint16_t kShnUndef = 0U;
static const uint32_t kRArmGlobDat = 21U;

}  // namespace

ElfSymbols::ElfSymbols() : loaded_(false) {}

void ElfSymbols::clear() {
    data_.clear();
    dynsym_ = SectionSlice();
    dynstr_ = SectionSlice();
    rel_sections_.clear();
    loaded_ = false;
}

bool ElfSymbols::loadFromFile(const std::string& path) {
    clear();
    if (path.empty()) {
        return false;
    }
    FILE* file = ::fopen(path.c_str(), "rb");
    if (file == NULL) {
        return false;
    }

    std::vector<uint8_t> buffer(65536U);
    size_t count = 0;
    bool overflow = false;
    while ((count = ::fread(&buffer[0], 1, buffer.size(), file)) > 0) {
        if (count > kMaxFileBytes - data_.size()) {
            overflow = true;
            break;
        }
        data_.insert(data_.end(), buffer.begin(),
                     buffer.begin() + static_cast<std::ptrdiff_t>(count));
    }
    const bool read_error = ::ferror(file) != 0;
    ::fclose(file);

    if (overflow || read_error) {
        clear();
        return false;
    }
    if (!parse()) {
        clear();
        return false;
    }
    return true;
}

bool ElfSymbols::loadFromBytes(const uint8_t* data, size_t len) {
    clear();
    if (data == NULL || len == 0 || len > kMaxFileBytes) {
        return false;
    }
    data_.assign(data, data + len);
    if (!parse()) {
        clear();
        return false;
    }
    return true;
}

bool ElfSymbols::loadFromBytes(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        clear();
        return false;
    }
    return loadFromBytes(&bytes[0], bytes.size());
}

bool ElfSymbols::copyAt(uint64_t offset, void* out, size_t len) const {
    if (offset > data_.size() || len > data_.size() - offset) {
        return false;
    }
    if (len > 0) {
        memcpy(out, &data_[static_cast<size_t>(offset)], len);
    }
    return true;
}

bool ElfSymbols::readU16Le(uint64_t offset, uint16_t& out) const {
    uint8_t b[2];
    if (!copyAt(offset, b, sizeof(b))) {
        return false;
    }
    out = static_cast<uint16_t>(static_cast<uint16_t>(b[0]) |
                                (static_cast<uint16_t>(b[1]) << 8));
    return true;
}

bool ElfSymbols::readU32Le(uint64_t offset, uint32_t& out) const {
    uint8_t b[4];
    if (!copyAt(offset, b, sizeof(b))) {
        return false;
    }
    out = static_cast<uint32_t>(b[0]) |
          (static_cast<uint32_t>(b[1]) << 8) |
          (static_cast<uint32_t>(b[2]) << 16) |
          (static_cast<uint32_t>(b[3]) << 24);
    return true;
}

bool ElfSymbols::inFile(const SectionSlice& sec) const {
    const uint64_t off = sec.offset;
    const uint64_t sz = sec.size;
    return off <= data_.size() && sz <= data_.size() - off;
}

bool ElfSymbols::readSection(uint64_t shoff, uint16_t index, SectionSlice& out) const {
    const uint64_t base = shoff + static_cast<uint64_t>(index) * kElf32ShdrSize;
    if (!readU32Le(base + 4U, out.type) ||
        !readU32Le(base + 16U, out.offset) ||
        !readU32Le(base + 20U, out.size) ||
        !readU32Le(base + 24U, out.link) ||
        !readU32Le(base + 36U, out.entsize)) {
        return false;
    }
    return true;
}

bool ElfSymbols::parse() {
    if (data_.size() < kElf32EhdrSize) {
        return false;
    }
    if (memcmp(&data_[0], kElfMagic, sizeof(kElfMagic)) != 0 ||
        data_[4] != kElfClass32 ||
        data_[5] != kElfData2Lsb) {
        return false;
    }

    uint16_t machine = 0;
    uint32_t shoff = 0;
    uint16_t shentsize = 0;
    uint16_t shnum = 0;
    if (!readU16Le(18U, machine) ||
        !readU32Le(32U, shoff) ||
        !readU16Le(46U, shentsize) ||
        !readU16Le(48U, shnum)) {
        return false;
    }
    if (machine != kEmArm || shentsize != kElf32ShdrSize || shnum == 0) {
        return false;
    }
    const uint64_t sh_table_bytes = static_cast<uint64_t>(shnum) * kElf32ShdrSize;
    if (static_cast<uint64_t>(shoff) > data_.size() ||
        sh_table_bytes > data_.size() - shoff) {
        return false;
    }

    bool found_dynsym = false;
    for (uint16_t i = 0; i < shnum; ++i) {
        SectionSlice sec;
        if (!readSection(shoff, i, sec)) {
            return false;
        }
        if (sec.type == kShtRel) {
            if (inFile(sec) && (sec.entsize == 0 || sec.entsize == kElf32RelSize)) {
                rel_sections_.push_back(sec);
            }
        } else if (sec.type == kShtDynsym) {
            if (!inFile(sec) || sec.link >= shnum) {
                return false;
            }
            if (sec.entsize != 0 && sec.entsize != kElf32SymSize) {
                return false;
            }
            SectionSlice strtab;
            if (!readSection(shoff, static_cast<uint16_t>(sec.link), strtab) ||
                strtab.type != kShtStrtab || !inFile(strtab)) {
                return false;
            }
            dynsym_ = sec;
            dynstr_ = strtab;
            found_dynsym = true;
        }
    }

    loaded_ = found_dynsym;
    return loaded_;
}

uint32_t ElfSymbols::findGotSlot(uint32_t sym_index) const {
    for (size_t s = 0; s < rel_sections_.size(); ++s) {
        const SectionSlice& rel = rel_sections_[s];
        const size_t entries = rel.size / kElf32RelSize;
        for (size_t i = 0; i < entries; ++i) {
            const uint64_t off = static_cast<uint64_t>(rel.offset) + i * kElf32RelSize;
            uint32_t r_offset = 0;
            uint32_t r_info = 0;
            if (!readU32Le(off, r_offset) || !readU32Le(off + 4U, r_info)) {
                continue;
            }
            const uint32_t r_sym = r_info >> 8;
            const uint32_t r_type = r_info & 0xffU;
            if (r_sym == sym_index && r_type == kRArmGlobDat) {
                return r_offset;
            }
        }
    }
    return 0;
}

bool ElfSymbols::findSymbol(const char* name, ElfSymbolInfo& out) const {
    out = ElfSymbolInfo();
    if (!loaded_ || name == NULL || *name == '\0') {
        return false;
    }
    const size_t wanted = strlen(name) + 1U;
    const size_t entries = dynsym_.size / kElf32SymSize;
    for (size_t i = 0; i < entries; ++i) {
        const uint64_t off = static_cast<uint64_t>(dynsym_.offset) + i * kElf32SymSize;
        uint32_t st_name = 0;
        uint32_t st_value = 0;
        uint32_t st_size = 0;
        uint16_t st_shndx = 0;
        if (!readU32Le(off + 0U, st_name) ||
            !readU32Le(off + 4U, st_value) ||
            !readU32Le(off + 8U, st_size) ||
            !readU16Le(off + 14U, st_shndx)) {
            continue;
        }
        if (st_shndx == kShnUndef || st_name >= dynstr_.size ||
            wanted > dynstr_.size - st_name) {
            continue;
        }
        if (memcmp(&data_[static_cast<size_t>(dynstr_.offset) + st_name], name, wanted) == 0) {
            out.value = st_value;
            out.size = st_size;
            out.got = findGotSlot(static_cast<uint32_t>(i));
            return true;
        }
    }
    return false;
}

bool ElfSymbols::findSymbol(const std::string& name, ElfSymbolInfo& out) const {
    return findSymbol(name.c_str(), out);
}

}  // namespace platform
}  // namespace carplay
