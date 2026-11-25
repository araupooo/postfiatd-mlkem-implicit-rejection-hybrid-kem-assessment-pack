#!/bin/sh
# make_sha256sums.sh — regenerate SHA256SUMS over every pack file except
# SHA256SUMS itself, build/ outputs and the harness binary. Full 64-char hashes.
set -eu
cd "$(dirname "$0")/.."
find . -type f \
    ! -path './SHA256SUMS' \
    ! -path './build/*' \
    ! -name 'mlkem_harness' \
    ! -path './outputs/reproduce.log' \
    -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
echo "SHA256SUMS regenerated: $(wc -l < SHA256SUMS) entries"
