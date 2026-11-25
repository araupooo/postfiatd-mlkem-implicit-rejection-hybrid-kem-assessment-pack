#!/bin/sh
# run_all.sh — one-command reproduce for the whole pack.
#   1. Fetches liboqs 0.14.0 (pinned tag; commit recorded in docs/environment.md).
#   2. Builds liboqs (static, lib only) and the harness.
#   3. Runs the harness (benchmarks, failure injection, timing, key reuse, hybrids).
#   4. Runs the source-trace check (postfiatd: no ML-KEM/KEM code).
#   5. Regenerates SHA256SUMS and verifies digests (exit non-zero on any failure).
# Usage: ./run_all.sh [bench_n] [timing_n]   (defaults: 200 1000)
# Network is needed once, to clone liboqs and postfiatd. Everything else is local.
set -eu
cd "$(dirname "$0")"
PACK_DIR="$PWD"
BENCH_N="${1:-200}"
TIMING_N="${2:-1000}"
LIBOQS_TAG="0.14.0"
LIBOQS_COMMIT="94b421ebb82405c843dba4e9aa521a56ee5a333d"
POSTFIATD_COMMIT="0085a1ff885d6a446369cf73a4430f75af22be55"

mkdir -p build outputs
if [ ! -d build/liboqs ]; then
    git clone --quiet --depth 1 --branch "$LIBOQS_TAG" https://github.com/open-quantum-safe/liboqs.git build/liboqs
fi
ACTUAL="$(git -C build/liboqs rev-parse HEAD)"
if [ "$ACTUAL" != "$LIBOQS_COMMIT" ]; then
    echo "ERROR: liboqs commit mismatch: got $ACTUAL want $LIBOQS_COMMIT" >&2
    exit 1
fi
if [ ! -f build/liboqs-install/lib/liboqs.a ]; then
    mkdir -p build/liboqs/build
    (cd build/liboqs/build && cmake -G'Unix Makefiles' \
        -DCMAKE_INSTALL_PREFIX="$PACK_DIR/build/liboqs-install" \
        -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_BUILD_TYPE=Release .. > "$PACK_DIR/build/liboqs-cmake.log" 2>&1)
    (cd build/liboqs/build && make -j2 > "$PACK_DIR/build/liboqs-make.log" 2>&1)
    (cd build/liboqs/build && make install > "$PACK_DIR/build/liboqs-install.log" 2>&1)
fi
gcc -O2 -Wall -Ibuild/liboqs-install/include -o build/mlkem_harness src/mlkem_harness.c \
    build/liboqs-install/lib/liboqs.a -lcrypto -lm

./build/mlkem_harness "$BENCH_N" "$TIMING_N" > outputs/harness.log 2>&1
HARNESS_RC=$?
cat outputs/harness.log
if [ "$HARNESS_RC" -ne 0 ]; then
    echo "ERROR: harness exited $HARNESS_RC" >&2
    exit "$HARNESS_RC"
fi

if [ ! -d build/postfiatd ]; then
    git clone --quiet --depth 1 https://github.com/postfiatorg/postfiatd.git build/postfiatd
fi
ACTUAL_PF="$(git -C build/postfiatd rev-parse HEAD)"
if [ "$ACTUAL_PF" != "$POSTFIATD_COMMIT" ]; then
    echo "ERROR: postfiatd HEAD moved: got $ACTUAL_PF want $POSTFIATD_COMMIT" >&2
    exit 1
fi
./scripts/trace_postfiatd.sh build/postfiatd > outputs/source-trace.log 2>&1
cat outputs/source-trace.log

./scripts/make_sha256sums.sh
./scripts/verify_digests.sh
echo "RUN_ALL_OK bench_n=$BENCH_N timing_n=$TIMING_N"
