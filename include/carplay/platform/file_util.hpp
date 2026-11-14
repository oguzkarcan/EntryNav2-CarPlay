#ifndef CARPLAY_PLATFORM_FILE_UTIL_HPP
#define CARPLAY_PLATFORM_FILE_UTIL_HPP

// Small, bounded file helpers for persistent state (POSIX open/fsync/rename; MinGW _open/_commit/
// MoveFileEx). Paths are narrow strings ('/' separators work on both systems).

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace platform {

enum FileReadResult {
    kFileReadOk = 0,
    kFileMissing = 1,
    kFileTooLarge = 2,  // larger than max_bytes (nothing returned)
    kFileReadError = 3  // exists but could not be read (permissions, not a regular file, I/O)
};

/// Reads a whole regular file of at most max_bytes. On POSIX symlinks are not followed.
FileReadResult readFileBounded(const std::string& path, size_t max_bytes, std::vector<uint8_t>& out);

/// Atomic replace: writes path + ".tmp" (created fresh, mode 0600 on POSIX), flushes it to stable
/// storage (fsync / _commit), renames it over `path` (rename / MoveFileEx REPLACE_EXISTING |
/// WRITE_THROUGH) and on POSIX fsyncs the directory. Readers see either the old or the new file.
/// The temp file is removed on failure.
bool writeFileAtomic(const std::string& path, const uint8_t* data, size_t len);

/// Creates `path` (one level; the parent must exist) with mode 0700 or, if it already exists as a
/// directory, tightens it to 0700 on POSIX. false if it is not a directory or cannot be created.
bool ensurePrivateDirectory(const std::string& path);

/// true if removed or already absent.
bool removeFile(const std::string& path);
/// Removes an EMPTY directory; true if removed or already absent.
bool removeDirectory(const std::string& path);
bool pathExists(const std::string& path);
/// POSIX permission bits (st_mode & 07777). Always false on Windows.
bool posixMode(const std::string& path, unsigned& mode_out);

/// dir + "/" + name (no doubling of a trailing separator).
std::string joinPath(const std::string& dir, const std::string& name);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_FILE_UTIL_HPP
