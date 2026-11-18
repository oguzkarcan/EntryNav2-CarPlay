#ifndef CARPLAY_PLATFORM_ELF_SYMBOLS_HPP
#define CARPLAY_PLATFORM_ELF_SYMBOLS_HPP

// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_elf.hpp, PolyForm Noncommercial License 1.0.0
//
// Read-only parser for ELF32 little-endian ARM shared libraries (`.dynsym`,
// `.dynstr`, and `SHT_REL` `R_ARM_GLOB_DAT` GOT relocations). Used to locate
// exported ALPS Bluetooth tables (`app`, `spp_info`, `spp_connected`) and
// validate their sizes and GOT slots without loading or executing the library.
//
// All ELF structures are decoded with explicit bounds checks from raw bytes so
// the code builds cleanly on non-Linux hosts without <elf.h>.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace platform {

struct ElfSymbolInfo {
    uint32_t value;  // virtual address relative to library load bias
    uint32_t size;   // st_size from .dynsym
    uint32_t got;    // R_ARM_GLOB_DAT relocation r_offset, or 0 if absent

    ElfSymbolInfo() : value(0), size(0), got(0) {}
};

class ElfSymbols {
public:
    static const size_t kMaxFileBytes = 64U * 1024U * 1024U;

    ElfSymbols();

    bool loadFromFile(const std::string& path);
    bool loadFromBytes(const uint8_t* data, size_t len);
    bool loadFromBytes(const std::vector<uint8_t>& bytes);
    void clear();

    bool isLoaded() const { return loaded_; }

    /// Looks up a defined symbol in `.dynsym` (`st_shndx != SHN_UNDEF`).
    /// Imported/undefined symbols are ignored.
    bool findSymbol(const char* name, ElfSymbolInfo& out) const;
    bool findSymbol(const std::string& name, ElfSymbolInfo& out) const;

private:
    struct SectionSlice {
        uint32_t offset;
        uint32_t size;
        uint32_t type;
        uint32_t link;
        uint32_t entsize;

        SectionSlice() : offset(0), size(0), type(0), link(0), entsize(0) {}
    };

    bool parse();
    bool copyAt(uint64_t offset, void* out, size_t len) const;
    bool inFile(const SectionSlice& sec) const;
    bool readU16Le(uint64_t offset, uint16_t& out) const;
    bool readU32Le(uint64_t offset, uint32_t& out) const;
    bool readSection(uint64_t shoff, uint16_t index, SectionSlice& out) const;
    uint32_t findGotSlot(uint32_t sym_index) const;

    std::vector<uint8_t> data_;
    SectionSlice dynsym_;
    SectionSlice dynstr_;
    std::vector<SectionSlice> rel_sections_;
    bool loaded_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_ELF_SYMBOLS_HPP
