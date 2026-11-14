#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>

#include "carplay/platform/file_util.hpp"

namespace carplay {
namespace platform {

std::string joinPath(const std::string& dir, const std::string& name) {
    if (dir.empty()) {
        return name;
    }
    const char last = dir[dir.size() - 1];
    if (last == '/' || last == '\\') {
        return dir + name;
    }
    return dir + "/" + name;
}

#ifdef _WIN32

FileReadResult readFileBounded(const std::string& path, size_t max_bytes, std::vector<uint8_t>& out) {
    out.clear();
    struct _stat64 st;
    if (_stat64(path.c_str(), &st) != 0) {
        return errno == ENOENT ? kFileMissing : kFileReadError;
    }
    if ((st.st_mode & _S_IFREG) == 0) {
        return kFileReadError;
    }
    if (static_cast<unsigned long long>(st.st_size) > max_bytes) {
        return kFileTooLarge;
    }
    const int fd = _open(path.c_str(), _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        return errno == ENOENT ? kFileMissing : kFileReadError;
    }
    out.resize(max_bytes + 1);
    size_t done = 0;
    while (done < out.size()) {
        const size_t want = out.size() - done;
        const int r = _read(fd, &out[done], static_cast<unsigned>(want > 0x10000000U ? 0x10000000U : want));
        if (r < 0) {
            _close(fd);
            out.clear();
            return kFileReadError;
        }
        if (r == 0) {
            break;
        }
        done += static_cast<size_t>(r);
    }
    _close(fd);
    if (done > max_bytes) {
        out.clear();
        return kFileTooLarge;  // grew after the stat
    }
    out.resize(done);
    return kFileReadOk;
}

bool writeFileAtomic(const std::string& path, const uint8_t* data, size_t len) {
    const std::string tmp = path + ".tmp";
    _unlink(tmp.c_str());
    const int fd = _open(tmp.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) {
        return false;
    }
    bool ok = true;
    size_t done = 0;
    while (ok && done < len) {
        const size_t want = len - done;
        const int w = _write(fd, data + done, static_cast<unsigned>(want > 0x10000000U ? 0x10000000U : want));
        if (w <= 0) {
            ok = false;
        } else {
            done += static_cast<size_t>(w);
        }
    }
    ok = ok && _commit(fd) == 0;  // FlushFileBuffers
    if (_close(fd) != 0) {
        ok = false;
    }
    ok = ok && MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) {
        _unlink(tmp.c_str());
    }
    return ok;
}

bool ensurePrivateDirectory(const std::string& path) {
    struct _stat64 st;
    if (_stat64(path.c_str(), &st) == 0) {
        return (st.st_mode & _S_IFDIR) != 0;
    }
    if (_mkdir(path.c_str()) != 0) {
        return false;
    }
    return true;
}

bool removeFile(const std::string& path) { return _unlink(path.c_str()) == 0 || errno == ENOENT; }

bool removeDirectory(const std::string& path) { return _rmdir(path.c_str()) == 0 || errno == ENOENT; }

bool pathExists(const std::string& path) {
    struct _stat64 st;
    return _stat64(path.c_str(), &st) == 0;
}

bool posixMode(const std::string&, unsigned& mode_out) {
    mode_out = 0;
    return false;
}

#else  // POSIX

static std::string parentDirectory(const std::string& path) {
    const size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return ".";
    }
    if (pos == 0) {
        return "/";
    }
    return path.substr(0, pos);
}

FileReadResult readFileBounded(const std::string& path, size_t max_bytes, std::vector<uint8_t>& out) {
    out.clear();
    int fd;
    do {
        fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return errno == ENOENT ? kFileMissing : kFileReadError;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return kFileReadError;
    }
    if (st.st_size < 0 || static_cast<unsigned long long>(st.st_size) > max_bytes) {
        close(fd);
        return kFileTooLarge;
    }
    out.resize(max_bytes + 1);
    size_t done = 0;
    while (done < out.size()) {
        const ssize_t r = read(fd, &out[done], out.size() - done);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            out.clear();
            return kFileReadError;
        }
        if (r == 0) {
            break;
        }
        done += static_cast<size_t>(r);
    }
    close(fd);
    if (done > max_bytes) {
        out.clear();
        return kFileTooLarge;  // grew after fstat
    }
    out.resize(done);
    return kFileReadOk;
}

bool writeFileAtomic(const std::string& path, const uint8_t* data, size_t len) {
    const std::string tmp = path + ".tmp";
    unlink(tmp.c_str());
    int fd;
    do {
        fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return false;
    }
    bool ok = fchmod(fd, 0600) == 0;
    size_t done = 0;
    while (ok && done < len) {
        const ssize_t w = write(fd, data + done, len - done);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            ok = false;
        } else if (w == 0) {
            ok = false;
        } else {
            done += static_cast<size_t>(w);
        }
    }
    ok = ok && fsync(fd) == 0;
    if (close(fd) != 0) {
        ok = false;
    }
    ok = ok && rename(tmp.c_str(), path.c_str()) == 0;
    if (!ok) {
        unlink(tmp.c_str());
        return false;
    }
    // Make the rename itself durable.
    const std::string dir = parentDirectory(path);
    const int dfd = open(dir.c_str(), O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) {
        fsync(dfd);  // best effort: some file systems refuse fsync on directories
        close(dfd);
    }
    return true;
}

bool ensurePrivateDirectory(const std::string& path) {
    struct stat st;
    if (lstat(path.c_str(), &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            return false;  // also refuses a symlink in place of the directory
        }
        if ((st.st_mode & 0777) != 0700) {
            return chmod(path.c_str(), 0700) == 0;
        }
        return true;
    }
    if (mkdir(path.c_str(), 0700) != 0) {
        return false;
    }
    return chmod(path.c_str(), 0700) == 0;  // umask may have removed bits; make it exact
}

bool removeFile(const std::string& path) { return unlink(path.c_str()) == 0 || errno == ENOENT; }

bool removeDirectory(const std::string& path) { return rmdir(path.c_str()) == 0 || errno == ENOENT; }

bool pathExists(const std::string& path) {
    struct stat st;
    return lstat(path.c_str(), &st) == 0;
}

bool posixMode(const std::string& path, unsigned& mode_out) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        mode_out = 0;
        return false;
    }
    mode_out = static_cast<unsigned>(st.st_mode) & 07777U;
    return true;
}

#endif

}  // namespace platform
}  // namespace carplay
