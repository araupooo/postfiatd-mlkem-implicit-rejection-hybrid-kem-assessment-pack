# Citations

Primary sources only. All were fetched live on 2026-11-25 and are cited
by exact section. Secondary coverage was not used for any specification
claim.

## FIPS 203 — ML-KEM

- **Source**: National Institute of Standards and Technology, FIPS 203,
  *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024.
- **URL**: `https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf`
- **Retrieved**: 2026-11-25 (PDF, 1,252,341 bytes).
- **Cited sections**:
  - Section 3.2, Table 1 — decapsulation failure definition and rates:
    ML-KEM-512 `2^-138.8`, ML-KEM-768 `2^-164.8`, ML-KEM-1024 `2^-174.8`.
  - Section 6.3, Algorithm 18 (`ML-KEM.Decaps_internal`) — implicit
    rejection: if the re-encrypted ciphertext does not match, `K' <- J(z||c)`;
    the implicit-reject flag is secret intermediate data, must be destroyed
    before the algorithm terminates, and must not be returned in any form.
  - Section 7.3, Algorithm 21 (`ML-KEM.Decaps`) — decapsulation always
    outputs a 32-byte shared secret after input checks (ciphertext length,
    decapsulation-key length, hash check `H(dk[384k:768k+32])`).
  - Section 8, Table 2 — approved parameter sets (k, eta1, eta2, du, dv).
  - Section 8, Table 3 — sizes in bytes: ML-KEM-512 ek 800 / dk 1632 /
    ct 768 / ss 32; ML-KEM-768 ek 1184 / dk 2400 / ct 1088 / ss 32;
    ML-KEM-1024 ek 1568 / dk 3168 / ct 1568 / ss 32.

## RFC 7748 — X25519

- **Source**: Langley, Hamburg, Turner, *Elliptic Curves for Security*,
  RFC 7748, Informational, January 2016.
- **URL**: `https://www.rfc-editor.org/rfc/rfc7748.txt`
- **Retrieved**: 2026-11-25 (39,298 bytes).
- **Cited sections**:
  - Section 5 — the X25519 function, Montgomery ladder pseudocode,
    `decodeUCoordinate` masking of the most significant bit, acceptance of
    non-canonical values reduced modulo p.
  - Section 5.2 — test vectors used by the harness self-test (full
    values; the harness checks both and prints them in
    `outputs/harness.log:5-6`):
    - scalar `a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4`,
      u `e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c` ->
      `c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552`;
    - scalar `4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d`,
      u `e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493` ->
      `95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957`.

## RFC 10024 — PQ/T hybrid key agreement for TLS 1.3

- **Source**: Kwiatkowski, Kampanakis, Westerbaan, Stebila,
  *Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for
  TLS 1.3*, RFC 10024, Standards Track, August 2026.
- **URL**: `https://www.rfc-editor.org/rfc/rfc10024.txt`
- **Retrieved**: 2026-11-25 (21,016 bytes).
- **Cited sections**:
  - Section 4.3 — shared secret: for X25519MLKEM768, the concatenation
    of the ML-KEM and X25519 shared secrets, 64 bytes; both parties must
    calculate the ECDHE part including the all-zero shared-secret check
    for X25519, and abort with an `illegal_parameter` alert if it fails.
  - Sections 7.1–7.3 — IANA registrations for X25519MLKEM768,
    SecP256r1MLKEM768, SecP384r1MLKEM1024.

## draft-connolly-cfrg-xwing-kem-11 — X-Wing

- **Source**: Connolly, Schwabe, Westerbaan, *X-Wing: general-purpose
  hybrid post-quantum KEM*, draft-connolly-cfrg-xwing-kem-11, 23 September
  2026, intended status Informational, expires 27 March 2027.
- **URL**: `https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/`
  (status page); text fetched from the IETF mirror
  `https://nic.funet.fi/pub/mirrors/ftp.ietf.org/internet-drafts/draft-connolly-cfrg-xwing-kem-11.txt`
- **Retrieved**: 2026-11-25 (61,105 bytes). Status confirmed live on the
  datatracker the same day: still an Internet-Draft, not an RFC.
- **Cited sections**:
  - Section 5.1 — fixed sizes: decapsulation key 32 bytes, encapsulation
    key 1216 bytes, ciphertext 1120 bytes, shared secret 32 bytes.
  - Section 5.2 — key generation via `SHAKE256(sk, 96)` expansion and
    `ML-KEM.KeyGen_internal`.
  - Section 5.3 — combiner:
    `SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)`,
    label `5c2e2f2f5e5c`.
  - Section 5.4 — encapsulation; section 5.5 — decapsulation (no
    all-zero X25519 check is specified).
  - Section 6 — security: IND-CCA security bounded by ML-KEM-768 IND-CCA
    and Curve25519 gap-CDH, modelling SHA3/SHAKE as a random oracle.
  - Section 6.1 — binding properties: X-Wing satisfies MAL-BIND-K-PK and
    MAL-BIND-K-CT; ML-KEM on its own does not achieve MAL-BIND-K-PK.
  - Appendix C — test vectors: marked TODO ("replace with test vectors
    that re-use..."); no published vectors exist as of this writing.

## liboqs 0.14.0

- **Source**: Open Quantum Safe, liboqs, release 0.14.0, 2025-07-10.
- **URL**: `https://github.com/open-quantum-safe/liboqs`
- **Commit**: `94b421ebb82405c843dba4e9aa521a56ee5a333d` (verified against
  the GitHub API on 2026-11-25).
- **Cited files**:
  - `docs/algorithms/kem/ml_kem.yml` — ML-KEM parameter sets, sizes,
    upstream (`pq-code-package/mlkem-native`), NIST level claims.
  - `src/kem/` — algorithm inventory: `bike`, `classic_mceliece`,
    `frodokem`, `hqc`, `kyber`, `ml_kem`, `ntruprime`. No `xwing`
    directory exists: liboqs 0.14.0 does not ship X-Wing.
  - `README.md` (Supported Algorithms) — only ML-KEM and ML-DSA
    implement final NIST standards in liboqs.

## postfiatd (pinned revision)

- **Source**: `https://github.com/postfiatorg/postfiatd`, branch `main`.
- **Commit**: `0085a1ff885d6a446369cf73a4430f75af22be55`
  (2026-10-10, "Merge pull request #50 from
  postfiatorg/hotfix/upstream-hardening-1.0.9" with body "1.0.9: backport
  the upstream 3.4.1 payment engine overflow fix"; verified against the
  GitHub API on 2026-11-25).
- **Cited files** (line numbers from the local checkout, verified with
  `grep -n`):
  - `include/xrpl/protocol/KeyType.h:28-31` —
    `enum class KeyType { secp256k1 = 0, ed25519 = 1 };`
  - `src/libxrpl/protocol/PublicKey.cpp:229,232` — `publicKeyType`
    returns only `ed25519` or `secp256k1`.
  - `src/libxrpl/protocol/SecretKey.cpp:263,269` — signing dispatches
    only on `KeyType::ed25519` and `KeyType::secp256k1`.
  - Whole-tree whole-word search for `KEM`, `decapsulat*`,
    `encapsulat*`, `Kyber`, `ML-KEM` over `src/` and `include/`: no
    matches (`outputs/source-trace.log:4`).
