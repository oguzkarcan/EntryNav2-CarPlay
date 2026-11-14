#!/bin/sh
# Fails if the git tree contains files that must never be committed: binary libraries or
# kernel modules (the car's proprietary BMW / supplier software), archives (e.g. the sysroot
# tarball), keys and certificates, a sysroot/ directory, or any file larger than 2 MB.
#
# Usage: scripts/ci/check_repo_content.sh [max_bytes]    (run from anywhere inside the repo)
# Checks the files tracked in the index (`git ls-files`), i.e. what a commit would contain.

set -eu

MAX_BYTES=${1:-2097152}
cd "$(git rev-parse --show-toplevel)"

# Paths exempt from the size limit only (never from the forbidden-name patterns).
SIZE_ALLOW_PREFIXES="third_party/monocypher/"

bad=0
count=0
LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT INT TERM
git ls-files -z | tr '\0' '\n' > "$LIST"

while IFS= read -r f; do
    [ -n "$f" ] || continue
    count=$((count + 1))
    base=${f##*/}
    case "$base" in
        *.so|*.so.*|*.ko|*.tar.gz|*.tgz|*.pk8|*.pem|*.p7b|*.der)
            echo "::error file=$f::forbidden file type: $f"
            bad=1
            ;;
    esac
    case "/$f" in
        */sysroot/*)
            echo "::error file=$f::file inside a sysroot/ directory: $f"
            bad=1
            ;;
    esac
    if [ -f "$f" ]; then
        size=$(wc -c < "$f" | tr -d ' ')
        if [ "$size" -gt "$MAX_BYTES" ]; then
            allowed=0
            for p in $SIZE_ALLOW_PREFIXES; do
                case "$f" in "$p"*) allowed=1 ;; esac
            done
            if [ "$allowed" -eq 0 ]; then
                echo "::error file=$f::file larger than $MAX_BYTES bytes ($size): $f"
                bad=1
            fi
        fi
    fi
done < "$LIST"

echo "checked $count tracked files (limit $MAX_BYTES bytes, size allow-list: $SIZE_ALLOW_PREFIXES)"
if [ "$bad" -ne 0 ]; then
    echo "repository content check FAILED: remove the files above (and from history if already pushed)"
    exit 1
fi
echo "repository content check passed"
