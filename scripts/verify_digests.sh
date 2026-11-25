#!/bin/sh
# verify_digests.sh — verify every entry in SHA256SUMS. Exits non-zero on
# any mismatch or missing file.
set -eu
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS
echo "DIGESTS_OK"
