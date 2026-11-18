#!/bin/sh
# Verify runtime dlopen() sonames and dlsym() symbols against C++ sources and SYSROOT.
#
# Usage:
#   scripts/ci/check_sysroot_symbols.sh [options]
#
# Options:
#   --sysroot PATH   Override SYSROOT directory (default: $SYSROOT or ../EntryNav2-CarPlay-Assets/sysroot)
#   --manifest PATH  Override manifest file (default: scripts/ci/sysroot_symbols.txt)
#   --sync-only      Only verify that C++ sources and the manifest are in sync
#   --self-test      Run built-in self-tests with a temporary compiler-built fake sysroot
#   -h, --help       Show help
#
# Environment:
#   SYSROOT          Path to extracted target rootfs (skipped with exit 0 if absent)
#   CC               C compiler used by --self-test (default: cc / gcc / clang)
#   READELF          Optional readelf binary override
#   NM               Optional nm binary override

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to run check_sysroot_symbols.sh" >&2
    exit 2
fi

export CARPLAY_REPO_ROOT="$REPO_ROOT"

python3 -I - "$@" <<'__SYSROOT_CHECK_PY__'
import argparse
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

SEARCH_DIRS = ("lib", "usr/lib", "usr/local/lib", "opt/hmi/lib")
SONAME_RE = re.compile(r"^lib[A-Za-z0-9_+-]+\.so(?:\.[0-9A-Za-z._-]+)?$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ManifestError(Exception):
    pass


class LibSpec:
    def __init__(self, name, required, mode, handle=None):
        self.name = name
        self.required = required
        self.mode = mode  # "any" or "all"
        self.handle = handle
        self.sources = []
        self.sonames = []  # list of (name, manifest_only)
        self.symbols = []  # list of (name, required, manifest_only)


def parse_manifest(path):
    if not os.path.isfile(path):
        raise ManifestError("manifest not found: %s" % path)

    libs = []
    seen_libs = set()
    cur = None

    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0]

            if cmd == "library":
                if len(parts) < 4 or len(parts) > 5:
                    raise ManifestError("%s:%d: expected: library <name> <required|optional> <any|all> [handle=<expr>]" % (path, lineno))
                name, req_s, mode = parts[1], parts[2], parts[3]
                if name in seen_libs:
                    raise ManifestError("%s:%d: duplicate library %r" % (path, lineno, name))
                if req_s not in ("required", "optional"):
                    raise ManifestError("%s:%d: invalid requirement %r" % (path, lineno, req_s))
                if mode not in ("any", "all"):
                    raise ManifestError("%s:%d: invalid mode %r" % (path, lineno, mode))
                handle = None
                if len(parts) == 5:
                    if not parts[4].startswith("handle=") or len(parts[4]) <= 7:
                        raise ManifestError("%s:%d: invalid handle attribute %r" % (path, lineno, parts[4]))
                    handle = parts[4][7:]
                cur = LibSpec(name, req_s == "required", mode, handle)
                seen_libs.add(name)
                libs.append(cur)

            elif cmd == "source":
                if cur is None or len(parts) != 2:
                    raise ManifestError("%s:%d: expected: source <path>" % (path, lineno))
                src_rel = parts[1].replace("\\", "/")
                if src_rel not in cur.sources:
                    cur.sources.append(src_rel)

            elif cmd == "soname":
                if cur is None or len(parts) not in (2, 3):
                    raise ManifestError("%s:%d: expected: soname <filename> [manifest_only]" % (path, lineno))
                manifest_only = False
                if len(parts) == 3:
                    if parts[2] != "manifest_only":
                        raise ManifestError("%s:%d: unknown soname flag %r" % (path, lineno, parts[2]))
                    manifest_only = True
                if any(s[0] == parts[1] for s in cur.sonames):
                    raise ManifestError("%s:%d: duplicate soname %r in %s" % (path, lineno, parts[1], cur.name))
                cur.sonames.append((parts[1], manifest_only))

            elif cmd == "symbol":
                if cur is None or len(parts) not in (3, 4):
                    raise ManifestError("%s:%d: expected: symbol <required|optional> <name> [manifest_only]" % (path, lineno))
                req_s, sym_name = parts[1], parts[2]
                if req_s not in ("required", "optional"):
                    raise ManifestError("%s:%d: invalid symbol requirement %r" % (path, lineno, req_s))
                manifest_only = False
                if len(parts) == 4:
                    if parts[3] != "manifest_only":
                        raise ManifestError("%s:%d: unknown symbol flag %r" % (path, lineno, parts[3]))
                    manifest_only = True
                if any(s[0] == sym_name for s in cur.symbols):
                    raise ManifestError("%s:%d: duplicate symbol %r in %s" % (path, lineno, sym_name, cur.name))
                cur.symbols.append((sym_name, req_s == "required", manifest_only))

            else:
                raise ManifestError("%s:%d: unknown directive %r" % (path, lineno, cmd))

    for lib in libs:
        if not lib.sources:
            raise ManifestError("library %s has no source entries" % lib.name)
        if not lib.sonames:
            raise ManifestError("library %s has no soname entries" % lib.name)

    return libs


def strip_cpp_comments(text):
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            i += 2
            while i < n and text[i] != "\n":
                i += 1
        elif ch == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
        elif ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c = text[i]
                out.append(c)
                i += 1
                if c == "\\" and i < n:
                    out.append(text[i])
                    i += 1
                elif c == quote:
                    break
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def decode_c_string_literal(raw_inner):
    # Handle common C escapes cleanly for soname / symbol string literals.
    return bytes(raw_inner, "utf-8").decode("unicode_escape")


def extract_string_literals(code):
    # Matches C string literals and merges adjacent literals separated by whitespace.
    lit_re = re.compile(r'(?:"((?:\\.|[^"\\])*)"\s*)+')
    single_re = re.compile(r'"((?:\\.|[^"\\])*)"')
    results = []
    for m in lit_re.finditer(code):
        parts = [decode_c_string_literal(sm.group(1)) for sm in single_re.finditer(m.group(0))]
        results.append("".join(parts))
    return results


def find_matching_delim(code, open_idx, open_ch, close_ch):
    depth = 0
    i = open_idx
    n = len(code)
    while i < n:
        ch = code[i]
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                if code[i] == "\\" and i + 1 < n:
                    i += 2
                elif code[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def split_top_level_args(arg_text):
    args = []
    cur = []
    depth_paren = 0
    depth_brack = 0
    depth_brace = 0
    i = 0
    n = len(arg_text)
    while i < n:
        ch = arg_text[i]
        if ch in ('"', "'"):
            quote = ch
            cur.append(ch)
            i += 1
            while i < n:
                c = arg_text[i]
                cur.append(c)
                i += 1
                if c == "\\" and i < n:
                    cur.append(arg_text[i])
                    i += 1
                elif c == quote:
                    break
            continue
        if ch == "(":
            depth_paren += 1
        elif ch == ")" and depth_paren > 0:
            depth_paren -= 1
        elif ch == "[":
            depth_brack += 1
        elif ch == "]" and depth_brack > 0:
            depth_brack -= 1
        elif ch == "{":
            depth_brace += 1
        elif ch == "}" and depth_brace > 0:
            depth_brace -= 1
        elif ch == "," and depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
            args.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def extract_string_arrays(code):
    arrays = {}
    arr_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\]\s*=\s*\{")
    for m in arr_re.finditer(code):
        name = m.group(1)
        brace_open = m.end() - 1
        brace_close = find_matching_delim(code, brace_open, "{", "}")
        if brace_close < 0:
            continue
        body = code[brace_open + 1:brace_close]
        strings = extract_string_literals(body)
        if strings:
            arrays[name] = strings
    return arrays


def detect_dlsym_helpers(code):
    # Returns dict: func_name -> (handle_arg_idx_or_None, sym_arg_idx)
    helpers = {}
    # Match function definitions whose body calls dlsym(...)
    fn_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*\{")
    for m in fn_re.finditer(code):
        fn_name = m.group(1)
        if fn_name in ("if", "for", "while", "switch", "catch"):
            continue
        params_raw = m.group(2).strip()
        body_open = m.end() - 1
        body_close = find_matching_delim(code, body_open, "{", "}")
        if body_close < 0:
            continue
        body = code[body_open + 1:body_close]
        dlsym_m = re.search(r"\bdlsym\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", body)
        if not dlsym_m:
            continue
        h_param = dlsym_m.group(1)
        s_param = dlsym_m.group(2)
        params = split_top_level_args(params_raw)
        param_names = []
        for p in params:
            # Extract trailing parameter identifier (before any default value)
            p_no_def = p.split("=", 1)[0].strip()
            toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", p_no_def)
            param_names.append(toks[-1] if toks else "")
        if s_param not in param_names:
            continue
        s_idx = param_names.index(s_param)
        h_idx = param_names.index(h_param) if h_param in param_names else None
        helpers[fn_name] = (h_idx, s_idx)
    return helpers


def parse_single_string_expr(expr):
    expr = expr.strip()
    if not expr.startswith('"'):
        return None
    # Verify the entire expression consists only of string literals + whitespace.
    rem = re.sub(r'"(?:\\.|[^"\\])*"', "", expr).strip()
    if rem:
        return None
    lits = extract_string_literals(expr)
    return "".join(lits) if lits else None


def extract_from_cpp(code):
    has_dl_calls = bool(re.search(r"\b(?:dlopen|dlsym)\s*\(", code))
    sonames = []
    for lit in extract_string_literals(code):
        if SONAME_RE.match(lit) and lit not in sonames:
            sonames.append(lit)

    helpers = detect_dlsym_helpers(code)
    arrays = extract_string_arrays(code)

    call_targets = {"dlsym": (0, 1)}
    call_targets.update(helpers)

    symbols = []  # list of (handle_expr_or_None, symbol_name)
    seen_pairs = set()

    # Match both direct calls and ::dlsym / helper calls
    target_pat = "|".join(re.escape(k) for k in call_targets)
    call_re = re.compile(r"(?<![A-Za-z0-9_])(" + target_pat + r")\s*\(")
    for m in call_re.finditer(code):
        fn = m.group(1)
        # Skip function declarations/definitions (followed by '{' or template def parameter types)
        open_paren = m.end() - 1
        close_paren = find_matching_delim(code, open_paren, "(", ")")
        if close_paren < 0:
            continue
        # Look ahead past whitespace: if '{' follows, this is a function definition, not a call.
        tail = code[close_paren + 1:].lstrip()
        if tail.startswith("{"):
            continue
        args = split_top_level_args(code[open_paren + 1:close_paren])
        h_idx, s_idx = call_targets[fn]
        if s_idx >= len(args):
            continue
        sym_expr = args[s_idx]
        handle_expr = args[h_idx].strip() if (h_idx is not None and h_idx < len(args)) else None

        lit = parse_single_string_expr(sym_expr)
        if lit is not None:
            pair = (handle_expr, lit)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                symbols.append(pair)
            continue

        arr_m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[.*\]$", sym_expr)
        if arr_m and arr_m.group(1) in arrays:
            for item in arrays[arr_m.group(1)]:
                pair = (handle_expr, item)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    symbols.append(pair)

    return has_dl_calls, sonames, symbols


def scan_repo_sources(repo_root):
    scanned = {}
    for base in ("src", "include"):
        root_dir = os.path.join(repo_root, base)
        if not os.path.isdir(root_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames.sort()
            for fname in sorted(filenames):
                if not fname.endswith((".cpp", ".hpp", ".cc", ".hh", ".c", ".h")):
                    continue
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, repo_root).replace(os.sep, "/")
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
                stripped = strip_cpp_comments(raw)
                has_dl, sonames, symbols = extract_from_cpp(stripped)
                scanned[rel] = {
                    "has_dl": has_dl,
                    "sonames": sonames,
                    "symbols": symbols,
                }
    return scanned


def verify_manifest_sync(repo_root, libs):
    scanned = scan_repo_sources(repo_root)
    errors = []

    manifest_sources = set()
    for lib in libs:
        for src in lib.sources:
            manifest_sources.add(src)
            if src not in scanned:
                errors.append("manifest references missing source file: %s (in %s)" % (src, lib.name))

    # 1. Every file with dlopen/dlsym or lib*.so* literals must be in the manifest.
    for rel, info in sorted(scanned.items()):
        if (info["has_dl"] or info["sonames"] or info["symbols"]) and rel not in manifest_sources:
            errors.append(
                "unmanifested dynamic loader usage in %s (sonames=%s, symbols=%d)"
                % (rel, info["sonames"], len([s for _, s in info["symbols"]]))
            )

    # 2. For every source file referenced by the manifest, union of non-manifest_only
    #    sonames and symbols must match extracted code values.
    for src in sorted(manifest_sources):
        if src not in scanned:
            continue
        info = scanned[src]
        code_sonames = set(info["sonames"])
        code_symbols = set(sym for _, sym in info["symbols"])

        groups = [lib for lib in libs if src in lib.sources]
        man_sonames = set()
        man_symbols = set()
        for g in groups:
            for sname, man_only in g.sonames:
                if not man_only:
                    man_sonames.add(sname)
            for sym, _, man_only in g.symbols:
                if not man_only:
                    man_symbols.add(sym)

        missing_sonames = sorted(code_sonames - man_sonames)
        extra_sonames = sorted(man_sonames - code_sonames)
        # Note: a shared header like evo_video.hpp is listed on multiple libraries, so
        # only require exact match on files that define/own symbols OR check union across
        # all groups referencing `src`. Because union across all groups referencing
        # evo_video.hpp is {libxsvideo.so.4, libdrm.so.2, libdrm_omap.so.1}, it matches
        # code_sonames of evo_video.hpp AND matches each individual .cpp file!
        if missing_sonames:
            errors.append(
                "%s: source references soname(s) missing from manifest: %s"
                % (src, ", ".join(missing_sonames))
            )
        if extra_sonames:
            # Allow extra_sonames only when `src` is a header-only file? No — manifest groups
            # using a header must list only sonames present in the header or in the .cpp;
            # check that every non-manifest_only soname of a group appears in at least one
            # of that group's sources! Let's check both ways cleanly below.
            pass

        missing_syms = sorted(code_symbols - man_symbols)
        extra_syms = sorted(man_symbols - code_symbols)
        if missing_syms:
            errors.append(
                "%s: source resolves symbol(s) missing from manifest: %s"
                % (src, ", ".join(missing_syms))
            )
        if extra_syms:
            # Only flag extra_syms if `src` is the primary .cpp (or check per-library below)
            pass

    # 3. Per-library check: every non-manifest_only soname and symbol of a library must
    #    be extracted from at least one of its `source` files, and handle-scoped groups
    #    must match handle expressions.
    for lib in libs:
        lib_code_sonames = set()
        lib_code_syms = set()
        lib_handle_syms = {}
        for src in lib.sources:
            info = scanned.get(src)
            if not info:
                continue
            lib_code_sonames.update(info["sonames"])
            for h_expr, sym in info["symbols"]:
                lib_code_syms.add(sym)
                if h_expr is not None:
                    lib_handle_syms.setdefault(h_expr, set()).add(sym)

        for sname, man_only in lib.sonames:
            if not man_only and sname not in lib_code_sonames:
                errors.append(
                    "library %s: manifest soname %r not found in sources %s"
                    % (lib.name, sname, lib.sources)
                )
        for sym, _, man_only in lib.symbols:
            if not man_only and sym not in lib_code_syms:
                errors.append(
                    "library %s: manifest symbol %r not found in sources %s"
                    % (lib.name, sym, lib.sources)
                )
        if lib.handle is not None:
            handle_syms = lib_handle_syms.get(lib.handle, set())
            man_non_only = set(sym for sym, _, man_only in lib.symbols if not man_only)
            missing_h = sorted(handle_syms - man_non_only)
            extra_h = sorted(man_non_only - handle_syms)
            if missing_h:
                errors.append(
                    "library %s (handle=%s): source resolves %s not in manifest"
                    % (lib.name, lib.handle, ", ".join(missing_h))
                )
            if extra_h:
                errors.append(
                    "library %s (handle=%s): manifest lists %s not resolved via %s"
                    % (lib.name, lib.handle, ", ".join(extra_h), lib.handle)
                )

    return errors


def resolve_in_sysroot(sysroot_abs, candidate_name):
    """Resolve `candidate_name` inside sysroot search dirs, mapping symlinks safely inside sysroot.

    Returns dict:
      status: "found" | "dangling" | "not_file" | "cycle" | "missing"
      entry_rel: e.g. "usr/lib/libasound.so.2"
      resolved_rel: e.g. "usr/lib/libasound.so.2.0.0"
      resolved_abs: host path inside sysroot
      chain: list of (rel_path, link_target_or_None)
      detail: human-readable note if not found
    """
    for sdir in SEARCH_DIRS:
        start_rel = posixpath.normpath(posixpath.join(sdir, candidate_name))
        start_host = os.path.join(sysroot_abs, start_rel)
        if not os.path.lexists(start_host):
            continue

        cur_rel = start_rel
        visited = set()
        chain = []
        for _ in range(32):
            if cur_rel in visited:
                return {
                    "status": "cycle",
                    "entry_rel": start_rel,
                    "resolved_rel": cur_rel,
                    "resolved_abs": None,
                    "chain": chain,
                    "detail": "symlink cycle at /%s" % cur_rel,
                }
            visited.add(cur_rel)
            cur_host = os.path.join(sysroot_abs, cur_rel)
            if not os.path.lexists(cur_host):
                return {
                    "status": "dangling",
                    "entry_rel": start_rel,
                    "resolved_rel": cur_rel,
                    "resolved_abs": None,
                    "chain": chain,
                    "detail": "dangling symlink target missing in sysroot: /%s" % cur_rel,
                }
            if os.path.islink(cur_host):
                target = os.readlink(cur_host)
                chain.append((cur_rel, target))
                if target.startswith("/"):
                    # Map absolute target into sysroot root without touching host rootfs.
                    mapped = posixpath.normpath(target.lstrip("/"))
                else:
                    parent = posixpath.dirname(cur_rel)
                    mapped = posixpath.normpath(posixpath.join(parent, target))
                # Strip any leading ".." that escaped sysroot virtual root (normpath on "/..." avoids it).
                vnorm = posixpath.normpath("/" + mapped).lstrip("/")
                cur_rel = vnorm
                continue

            chain.append((cur_rel, None))
            if os.path.isfile(cur_host):
                return {
                    "status": "found",
                    "entry_rel": start_rel,
                    "resolved_rel": cur_rel,
                    "resolved_abs": cur_host,
                    "chain": chain,
                    "detail": "",
                }
            return {
                "status": "not_file",
                "entry_rel": start_rel,
                "resolved_rel": cur_rel,
                "resolved_abs": None,
                "chain": chain,
                "detail": "target is not a regular file: /%s" % cur_rel,
            }

        return {
            "status": "cycle",
            "entry_rel": start_rel,
            "resolved_rel": cur_rel,
            "resolved_abs": None,
            "chain": chain,
            "detail": "too many symlink hops (>32)",
        }

    return {
        "status": "missing",
        "entry_rel": None,
        "resolved_rel": None,
        "resolved_abs": None,
        "chain": [],
        "detail": "not found in %s" % ", ".join(SEARCH_DIRS),
    }


def find_nearby_sonames(sysroot_abs, soname):
    stem = soname.split(".so", 1)[0] + ".so"
    hits = []
    for sdir in SEARCH_DIRS:
        dpath = os.path.join(sysroot_abs, sdir)
        if not os.path.isdir(dpath):
            continue
        for entry in sorted(os.listdir(dpath)):
            if entry == stem or entry.startswith(stem + "."):
                hits.append(posixpath.join(sdir, entry))
    return hits


def detect_elf_tool():
    readelf_env = os.environ.get("READELF", "").strip()
    nm_env = os.environ.get("NM", "").strip()
    readelf = shutil.which(readelf_env) if readelf_env else shutil.which("readelf")
    nm = shutil.which(nm_env) if nm_env else shutil.which("nm")
    return readelf, nm


def read_exported_symbols(elf_path, readelf_bin, nm_bin):
    """Return dict: base_symbol_name -> sorted list of raw dynsym names (including @VER / @@VER)."""
    exports = {}

    if readelf_bin:
        try:
            proc = subprocess.run(
                [readelf_bin, "-W", "--dyn-syms", elf_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError:
            proc = None
        if proc is not None and proc.returncode == 0:
            # Format: Num: Value Size Type Bind Vis Ndx Name
            row_re = re.compile(
                r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(GLOBAL|WEAK)\s+(DEFAULT|PROTECTED)\s+(\S+)\s+(\S+)"
            )
            for line in proc.stdout.splitlines():
                m = row_re.match(line)
                if not m:
                    continue
                sym_type, _bind, _vis, ndx, raw_name = m.groups()
                if ndx in ("UND", "ABS"):
                    continue
                if sym_type == "SECTION":
                    continue
                base = raw_name.split("@", 1)[0]
                if not base:
                    continue
                exports.setdefault(base, [])
                if raw_name not in exports[base]:
                    exports[base].append(raw_name)
            return exports

    if nm_bin:
        try:
            proc = subprocess.run(
                [nm_bin, "-D", "--defined-only", elf_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError:
            proc = None
        if proc is not None and proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                sym_code, raw_name = parts[-2], parts[-1]
                if sym_code == "A":
                    continue
                base = raw_name.split("@", 1)[0]
                exports.setdefault(base, [])
                if raw_name not in exports[base]:
                    exports[base].append(raw_name)
            return exports

    raise RuntimeError("neither readelf nor nm could inspect ELF symbols of %s" % elf_path)


def check_sysroot(sysroot_path, libs):
    sysroot_abs = os.path.abspath(sysroot_path)
    readelf_bin, nm_bin = detect_elf_tool()
    if not readelf_bin and not nm_bin:
        print("error: neither 'readelf' nor 'nm' found in PATH", file=sys.stderr)
        return 2

    print("Sysroot: %s" % sysroot_abs)
    print("Search dirs: %s" % ", ".join(SEARCH_DIRS))
    print("ELF tool: %s" % (readelf_bin or nm_bin))
    print()

    req_failures = 0
    opt_warnings = 0
    libs_ok = 0

    for lib in libs:
        req_tag = "required" if lib.required else "optional"
        print("=== %s (%s, mode=%s) ===" % (lib.name, req_tag, lib.mode))
        print("  sources: %s" % ", ".join(lib.sources))

        resolved_dsos = []  # list of (soname, resolved_rel, exports_dict)

        for sname, _man_only in lib.sonames:
            res = resolve_in_sysroot(sysroot_abs, sname)
            if res["status"] == "found":
                try:
                    exports = read_exported_symbols(res["resolved_abs"], readelf_bin, nm_bin)
                except RuntimeError as exc:
                    print("  [FAIL] %s -> /%s: %s" % (sname, res["resolved_rel"], exc))
                    continue
                link_note = ""
                if res["entry_rel"] != res["resolved_rel"]:
                    link_note = " (via /%s)" % res["entry_rel"]
                print("  [FOUND] %s -> /%s%s [%d exported symbols]" % (sname, res["resolved_rel"], link_note, len(exports)))
                resolved_dsos.append((sname, res["resolved_rel"], exports))
                if lib.mode == "any":
                    break
            else:
                nearby = find_nearby_sonames(sysroot_abs, sname)
                nearby_note = ("; nearby in sysroot: %s" % ", ".join("/" + h for h in nearby)) if nearby else ""
                print("  [MISS]  %s: %s%s" % (sname, res["detail"], nearby_note))

        soname_ok = (len(resolved_dsos) > 0) if lib.mode == "any" else (len(resolved_dsos) == len(lib.sonames))
        lib_failed = False

        if not soname_ok:
            if lib.required:
                print("  STATUS: FAIL (missing required soname)")
                req_failures += 1
                lib_failed = True
            else:
                print("  STATUS: OPTIONAL-MISSING (optional library not present in sysroot)")
                opt_warnings += 1

        if lib.symbols:
            if not resolved_dsos:
                for sym_name, sym_req, _ in lib.symbols:
                    tag = "required" if sym_req else "optional"
                    print("  [SKIP]  (%s) %s (no resolved DSO)" % (tag, sym_name))
            else:
                miss_req = 0
                miss_opt = 0
                for sym_name, sym_req, _ in lib.symbols:
                    providers = []
                    for sname, _rrel, exports in resolved_dsos:
                        if sym_name in exports:
                            providers.append((sname, exports[sym_name]))
                    if providers:
                        if len(resolved_dsos) > 1:
                            prov_s = ", ".join("%s (%s)" % (sn, "/".join(raw)) for sn, raw in providers)
                        else:
                            raw = providers[0][1]
                            ver_notes = [r for r in raw if r != sym_name]
                            prov_s = ("versioned: %s" % ", ".join(ver_notes)) if ver_notes else "defined"
                        tag = "required" if sym_req else "optional"
                        print("  [OK]    (%s) %s [%s]" % (tag, sym_name, prov_s))
                    else:
                        if sym_req:
                            print("  [MISS]  (required) %s" % sym_name)
                            miss_req += 1
                        else:
                            print("  [MISS]  (optional) %s" % sym_name)
                            miss_opt += 1
                if miss_req > 0:
                    if lib.required:
                        req_failures += miss_req
                        lib_failed = True
                        print("  STATUS: FAIL (%d missing required symbol(s))" % miss_req)
                    else:
                        opt_warnings += miss_req
                if miss_opt > 0:
                    opt_warnings += miss_opt

        if not lib_failed and soname_ok:
            libs_ok += 1
            print("  STATUS: OK")
        elif not lib_failed and not lib.required:
            libs_ok += 1
        print()

    print("Summary: %d/%d library groups satisfied, %d required error(s), %d optional warning(s)"
          % (libs_ok, len(libs), req_failures, opt_warnings))
    return 1 if req_failures > 0 else 0


def find_c_compiler():
    for cand in (os.environ.get("CC", "").strip(), "cc", "gcc", "clang"):
        if cand and shutil.which(cand):
            return shutil.which(cand)
    return None


def compile_test_so(cc, out_path, c_source, version_script=None):
    with tempfile.TemporaryDirectory() as bdir:
        src = os.path.join(bdir, "lib.c")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(c_source)
        cmd = [cc, "-shared", "-fPIC", src, "-o", out_path]
        if version_script is not None:
            ver = os.path.join(bdir, "lib.ver")
            with open(ver, "w", encoding="utf-8") as fh:
                fh.write(version_script)
            cmd.append("-Wl,--version-script=" + ver)
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError("compiler failed (%s): %s" % (" ".join(cmd), proc.stderr.strip()))


def run_self_test(repo_root, real_manifest):
    cc = find_c_compiler()
    if not cc:
        print("FAIL: no C compiler (cc/gcc/clang) found for --self-test", file=sys.stderr)
        return 1

    readelf_bin, nm_bin = detect_elf_tool()
    if not readelf_bin and not nm_bin:
        print("FAIL: neither readelf nor nm found for --self-test", file=sys.stderr)
        return 1

    print("Running check_sysroot_symbols.sh --self-test (CC=%s, tool=%s)" % (cc, readelf_bin or nm_bin))

    # 1. Verify real repo manifest stays in sync with real C++ sources.
    libs_real = parse_manifest(real_manifest)
    sync_errs = verify_manifest_sync(repo_root, libs_real)
    if sync_errs:
        print("[FAIL] real repo manifest sync: %s" % sync_errs)
        return 1
    print("[PASS] 1. real repo source <-> manifest sync")

    with tempfile.TemporaryDirectory(prefix="carplay_sysroot_selftest_") as tmp:
        fake_repo = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(fake_repo, "src", "platform"))
        os.makedirs(os.path.join(fake_repo, "include"))

        # Synthetic C++ sources matching a synthetic manifest.
        with open(os.path.join(fake_repo, "src", "platform", "mod_a.cpp"), "w", encoding="utf-8") as fh:
            fh.write(
                '#include <dlfcn.h>\n'
                'template <typename Fn>\n'
                'bool loadSym(void* h, const char* name, Fn& out) {\n'
                '    void* p = dlsym(h, name);\n'
                '    return p != 0;\n'
                '}\n'
                'void initA() {\n'
                '    void* h = dlopen("libalpha.so.1", RTLD_NOW);\n'
                '    void* f1 = 0; void* f2 = 0; void* f3 = 0;\n'
                '    loadSym(h, "alpha_req", f1);\n'
                '    loadSym(h, "alpha_ver", f2);\n'
                '    loadSym(h, "alpha_opt", f3);\n'
                '}\n'
            )
        with open(os.path.join(fake_repo, "src", "platform", "mod_b.cpp"), "w", encoding="utf-8") as fh:
            fh.write(
                '#include <dlfcn.h>\n'
                'static const char* const kBetaSyms[] = { "beta_one", "beta_two" };\n'
                'void initB() {\n'
                '    void* h = dlopen("libbeta.so.2", RTLD_NOW);\n'
                '    dlsym(h, kBetaSyms[0]);\n'
                '    dlsym(h, kBetaSyms[1]);\n'
                '}\n'
            )
        with open(os.path.join(fake_repo, "src", "platform", "mod_opt.cpp"), "w", encoding="utf-8") as fh:
            fh.write(
                '#include <dlfcn.h>\n'
                'void probeOpt() {\n'
                '    dlopen("liboptprobe.so.9", RTLD_LAZY);\n'
                '}\n'
            )

        syn_manifest = os.path.join(fake_repo, "manifest.txt")
        with open(syn_manifest, "w", encoding="utf-8") as fh:
            fh.write(
                "library libalpha required any\n"
                "  source src/platform/mod_a.cpp\n"
                "  soname libalpha.so.1\n"
                "  symbol required alpha_req\n"
                "  symbol required alpha_ver\n"
                "  symbol optional alpha_opt\n\n"
                "library libbeta required any\n"
                "  source src/platform/mod_b.cpp\n"
                "  soname libbeta.so.2\n"
                "  symbol required beta_one\n"
                "  symbol required beta_two\n\n"
                "library liboptprobe optional any\n"
                "  source src/platform/mod_opt.cpp\n"
                "  soname liboptprobe.so.9\n"
            )

        syn_libs = parse_manifest(syn_manifest)
        if verify_manifest_sync(fake_repo, syn_libs):
            print("[FAIL] 2a. synthetic sync failed unexpectedly")
            return 1

        # Build fake sysroot with two real compiled .so files:
        #   - usr/lib/libalpha.so.1 -> libalpha.so.1.0.0 (relative symlink, versioned symbol)
        #   - opt/hmi/lib/libbeta.so.2.0.0 + usr/local/lib/libbeta.so.2 -> /opt/hmi/lib/libbeta.so.2.0.0 (absolute symlink mapped inside sysroot)
        sys_pass = os.path.join(tmp, "sysroot_pass")
        for sub in ("lib", "usr/lib", "usr/local/lib", "opt/hmi/lib"):
            os.makedirs(os.path.join(sys_pass, sub))

        alpha_so = os.path.join(sys_pass, "usr/lib/libalpha.so.1.0.0")
        compile_test_so(
            cc,
            alpha_so,
            "int alpha_req(void) { return 1; }\nint alpha_ver(void) { return 2; }\n",
            version_script="ALPHA_1.0 {\n  global:\n    alpha_req;\n    alpha_ver;\n  local:\n    *;\n};\n",
        )
        os.symlink("libalpha.so.1.0.0", os.path.join(sys_pass, "usr/lib/libalpha.so.1"))

        beta_so = os.path.join(sys_pass, "opt/hmi/lib/libbeta.so.2.0.0")
        compile_test_so(
            cc,
            beta_so,
            "int beta_one(void) { return 1; }\nint beta_two(void) { return 2; }\n",
        )
        os.symlink("/opt/hmi/lib/libbeta.so.2.0.0", os.path.join(sys_pass, "usr/local/lib/libbeta.so.2"))

        rc_pass = check_sysroot(sys_pass, syn_libs)
        if rc_pass != 0:
            print("[FAIL] 2. passing fake sysroot returned non-zero (%d)" % rc_pass)
            return 1
        print("[PASS] 2. fake sysroot pass (relative symlink, absolute sysroot-mapped symlink, versioned symbol, optional missing)")

        # 3. Missing required symbol must fail.
        sys_miss_sym = os.path.join(tmp, "sysroot_miss_sym")
        for sub in ("lib", "usr/lib", "usr/local/lib", "opt/hmi/lib"):
            os.makedirs(os.path.join(sys_miss_sym, sub))
        compile_test_so(
            cc,
            os.path.join(sys_miss_sym, "usr/lib/libalpha.so.1"),
            "int alpha_req(void) { return 1; }\n",
        )
        compile_test_so(
            cc,
            os.path.join(sys_miss_sym, "usr/local/lib/libbeta.so.2"),
            "int beta_one(void) { return 1; }\nint beta_two(void) { return 2; }\n",
        )
        rc_miss_sym = check_sysroot(sys_miss_sym, syn_libs)
        if rc_miss_sym == 0:
            print("[FAIL] 3. missing required symbol unexpectedly succeeded")
            return 1
        print("[PASS] 3. missing required symbol detected and failed (rc=%d)" % rc_miss_sym)

        # 4. Absolute dangling symlink must fail and report missing target.
        sys_dangling = os.path.join(tmp, "sysroot_dangling")
        for sub in ("lib", "usr/lib", "usr/local/lib", "opt/hmi/lib"):
            os.makedirs(os.path.join(sys_dangling, sub))
        os.symlink("/opt/app/missing/libalpha.so.1.0.0", os.path.join(sys_dangling, "usr/lib/libalpha.so.1"))
        compile_test_so(
            cc,
            os.path.join(sys_dangling, "usr/local/lib/libbeta.so.2"),
            "int beta_one(void) { return 1; }\nint beta_two(void) { return 2; }\n",
        )
        rc_dangling = check_sysroot(sys_dangling, syn_libs)
        if rc_dangling == 0:
            print("[FAIL] 4. absolute dangling symlink unexpectedly succeeded")
            return 1
        print("[PASS] 4. absolute dangling symlink detected and failed (rc=%d)" % rc_dangling)

        # 5. Source/manifest disagreement must fail.
        with open(os.path.join(fake_repo, "src", "platform", "mod_a.cpp"), "a", encoding="utf-8") as fh:
            fh.write('void extra() { void* p = 0; loadSym(p, "alpha_unlisted", p); }\n')
        drift_errs = verify_manifest_sync(fake_repo, syn_libs)
        if not drift_errs:
            print("[FAIL] 5. source/manifest disagreement not detected")
            return 1
        print("[PASS] 5. source/manifest disagreement detected: %s" % drift_errs[0])

        # 6. Absent SYSROOT CLI check skips cleanly with exit 0.
        script_path = os.path.join(repo_root, "scripts", "ci", "check_sysroot_symbols.sh")
        missing_sysroot = os.path.join(tmp, "does_not_exist")
        proc = subprocess.run(
            ["sh", script_path, "--sysroot", missing_sysroot],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0 or "SKIP:" not in proc.stdout:
            print("[FAIL] 6. absent sysroot should exit 0 with SKIP message (rc=%d, out=%r)" % (proc.returncode, proc.stdout))
            return 1
        print("[PASS] 6. absent SYSROOT skips cleanly with exit 0")

    print("self-test: all 6 checks passed")
    return 0


def main():
    repo_root = os.environ["CARPLAY_REPO_ROOT"]
    default_manifest = os.path.join(repo_root, "scripts", "ci", "sysroot_symbols.txt")
    default_sysroot = os.environ.get("SYSROOT", "").strip()
    if not default_sysroot:
        default_sysroot = os.path.normpath(os.path.join(repo_root, "..", "EntryNav2-CarPlay-Assets", "sysroot"))

    parser = argparse.ArgumentParser(
        prog="check_sysroot_symbols.sh",
        description="Verify runtime dlopen() sonames and dlsym() symbols against sources and SYSROOT.",
    )
    parser.add_argument("--sysroot", default=default_sysroot, help="Target sysroot directory")
    parser.add_argument("--manifest", default=default_manifest, help="Symbol/soname manifest file")
    parser.add_argument("--sync-only", action="store_true", help="Only check source <-> manifest sync")
    parser.add_argument("--self-test", action="store_true", help="Run built-in fake-sysroot self-test")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test(repo_root, args.manifest)

    try:
        libs = parse_manifest(args.manifest)
    except ManifestError as exc:
        print("MANIFEST ERROR: %s" % exc, file=sys.stderr)
        return 2

    sync_errors = verify_manifest_sync(repo_root, libs)
    if sync_errors:
        print("SYNC CHECK FAILED:", file=sys.stderr)
        for err in sync_errors:
            print("  - %s" % err, file=sys.stderr)
        return 1
    print("Source <-> manifest sync OK (%d library groups, %s)" % (len(libs), os.path.relpath(args.manifest, repo_root)))

    if args.sync_only:
        return 0

    if not os.path.isdir(args.sysroot):
        print("SKIP: sysroot directory not found: %s (set SYSROOT=/path/to/sysroot to run ELF verification)" % args.sysroot)
        return 0

    return check_sysroot(args.sysroot, libs)


if __name__ == "__main__":
    sys.exit(main())
__SYSROOT_CHECK_PY__
