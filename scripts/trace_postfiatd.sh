#!/bin/sh
# trace_postfiatd.sh — reproduce the source trace: postfiatd contains no
# ML-KEM / KEM / decapsulation code and only two key types. Prints every
# match with file and line number (grep -n on the local checkout), so the
# claim "nothing to trace" is checkable. Usage: ./scripts/trace_postfiatd.sh <postfiatd-checkout>
set -eu
D="${1:?usage: trace_postfiatd.sh <postfiatd-checkout>}"
echo "TRACE postfiatd checkout: $D"
echo "TRACE HEAD: $(git -C "$D" rev-parse HEAD) $(git -C "$D" log -1 --format='%ci %s')"
echo "--- whole-word matches for KEM / decapsulat / encapsulat / Kyber / ML-KEM (expect none) ---"
if grep -r -n -w -E 'KEM|decapsulat|encapsulat|Kyber|ML-KEM' "$D/src" "$D/include" --include='*.cpp' --include='*.h' ; then
    echo "TRACE whole-word KEM matches: FOUND (see above)"
else
    echo "TRACE whole-word KEM matches: NONE"
fi
echo "--- case-insensitive 'kem' substring matches (expect only makeMemberName / makeMptID false positives) ---"
grep -r -n -i -E 'kem' "$D/src" "$D/include" --include='*.cpp' --include='*.h' || echo "TRACE kem substring matches: NONE"
echo "--- KeyType enum (expect exactly secp256k1 and ed25519) ---"
grep -n -E 'secp256k1|ed25519|enum class KeyType' "$D/include/xrpl/protocol/KeyType.h"
echo "--- key-type use sites ---"
grep -rn -E 'KeyType::(secp256k1|ed25519)' "$D/src/libxrpl/protocol/PublicKey.cpp" "$D/src/libxrpl/protocol/SecretKey.cpp"
echo "--- KEM-like filenames (expect none) ---"
find "$D/src" "$D/include" -iname '*kem*' -o -iname '*kyber*' -o -iname '*mlkem*' -o -iname '*ml-kem*' || true
echo "TRACE_DONE"
