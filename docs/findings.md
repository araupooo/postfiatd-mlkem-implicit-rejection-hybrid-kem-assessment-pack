# Ranked findings

Severity is scored on impact if the behaviour is mishandled in a
deployment, not on the mere existence of the behaviour. Each finding
carries its evidence label (MEASURED / SPEC-DERIVED / SIMULATED /
UNSUPPORTED) and a pointer to the raw output line in `docs/claim-index.md`.

## F-01 — HIGH (MEASURED): postfiatd has no ML-KEM code at all

At pinned commit `0085a1ff885d6a446369cf73a4430f75af22be55`, postfiatd
contains no ML-KEM, KEM, encapsulation, or decapsulation code: zero
whole-word matches for `KEM`, `decapsulat*`, `encapsulat*`, `Kyber`,
`ML-KEM` across `src/` and `include/`. The only key types are
`secp256k1` and `ed25519` (`include/xrpl/protocol/KeyType.h:28-31`).
Consequence: there is no decapsulation-failure handling in postfiatd to
trace, audit, or migrate. Any ML-KEM deployment would be new code, not a
migration of existing handling, and it must be designed from the
FIPS 203 requirements rather than adapted from existing key handling.

## F-02 — MEDIUM (MEASURED): implicit rejection is silent — no error is ever returned

For all three parameter sets, every well-formed-length invalid ciphertext
decapsulated successfully (`OQS_SUCCESS`) to a 32-byte secret different
from the reference secret: 3 bit-flips, 32 random ciphertexts, and 1
all-zero ciphertext per parameter set (108 invalid decapsulations, 0
errors). This matches FIPS 203 section 6.3 / Algorithm 18: on mismatch
the output is replaced with `J(z||c)` and a 32-byte value is always
returned. Consequence: a caller that treats "decapsulation succeeded" as
"ciphertext authentic" is wrong by construction. Authentication of the
peer must come from elsewhere (for example, a MAC or signature over the
session transcript keyed by the shared secret); the KEM alone never
signals failure.

## F-03 — LOW (MEASURED): rejected outputs are distinct per invalid ciphertext

All 32 random-ciphertext rejected outputs per parameter set were distinct
(96/96), and all 9 bit-flip outputs differed from the reference secret and
from each other by SHA-256 digest. This is consistent with the
specification's `J(z||c)` construction binding the rejected output to the
presented ciphertext. No output reuse or collision was observed. The
rejected value is still deterministic for a given (key, ciphertext) pair:
replaying the same invalid ciphertext reproduces the same rejected secret,
so it must never be reused as a session key across sessions.

## F-04 — LOW (MEASURED): no timing signal at wall-clock resolution — but this proves nothing about constant-time behaviour

ML-KEM-768 decapsulation, n=1000 each: valid mean 19.170 µs, invalid mean
18.832 µs, medians identical at 18.297 µs, invalid/valid ratio 0.9824,
median difference 0.000 µs. No timing signal is observable at this coarse
resolution. This is a wall-clock comparison on a shared vCPU, not a
constant-time proof; it does not rule out a timing side channel in a
production implementation. A dedicated side-channel evaluation is still
required before deployment.

## F-05 — MEDIUM (MEASURED): key reuse is safe for correctness, unsafe to assume for replay protection

Under one ML-KEM-768 keypair, 100 encaps/decaps pairs all matched and all
100 ciphertexts were distinct. Replaying the first ciphertext
decapsulated successfully to the same secret, and decapsulating a
ciphertext under the wrong decapsulation key returned success with a
wrong secret (silent key confusion). ML-KEM provides no replay protection
and no key-mismatch signal. Consequences: shared secrets must be
single-use per session and bound to the session context; a replayed
ciphertext replays the session key; a ciphertext delivered to the wrong
key yields a wrong key with no error, so the protocol must detect that
through authenticated transcript binding.

## F-06 — HIGH (SPEC-DERIVED + MEASURED): X-Wing (draft-11) has no all-zero X25519 check

draft-11 section 5.5 decapsulation computes the combiner over whatever
`ss_X` the X25519 step produces, with no check. Measured: an all-zero
X25519 ciphertext part decapsulates to a value under the X-Wing combiner
(return code 0). The same input under the RFC 10024 combiner aborts
(return code -2), as RFC 10024 section 4.3 requires. An implementation
following draft-11 alone silently accepts a degenerate X25519
contribution, weakening the hybrid to ML-KEM-only security without any
signal. Any X-Wing deployment must add the all-zero check (see P0 in
`docs/remediation.md`).

## F-07 — MEDIUM (SPEC-DERIVED): X-Wing is still a draft; the TLS hybrid is already an RFC

draft-connolly-cfrg-xwing-kem-11 (23 September 2026) is an
Internet-Draft, intended status Informational, expiring 27 March 2027.
X25519MLKEM768 for TLS 1.3 is a published standard (RFC 10024, Standards
Track, August 2026). Depending on draft-11 for non-TLS use carries change
risk: the label, the combiner, or the section numbering may still move.
Additionally, draft-11 Appendix C test vectors are marked TODO — no
published vectors exist, so independent implementations cannot currently
be cross-checked against the authors' vectors.

## F-08 — LOW (MEASURED): liboqs 0.14.0 does not ship X-Wing or expose ML-KEM.KeyGen_internal

liboqs 0.14.0 has no X-Wing KEM (`src/kem/` contains `bike`,
`classic_mceliece`, `frodokem`, `hqc`, `kyber`, `ml_kem`, `ntruprime`
only) and no API for `ML-KEM.KeyGen_internal`, so draft-11 section 5.2
seed-expansion key generation cannot be reproduced with liboqs. The
harness used independent ML-KEM-768 and X25519 keypairs (labelled
deviation, `outputs/harness.log:82`). The combiner, encapsulation, and
decapsulation measurements are unaffected, but a deployment that needs
the draft's 32-byte seed key format must use a different library or
implement `KeyGen_internal` itself.

## F-09 — INFO (MEASURED): sizes and speeds confirmed

All three parameter-set sizes match FIPS 203 Table 3 exactly. Mean
encaps/decaps on this VM (n=200): ML-KEM-512 9.18 / 12.11 µs,
ML-KEM-768 14.86 / 18.70 µs, ML-KEM-1024 19.04 / 25.38 µs. Hybrid
encaps/decaps (n=200) are dominated by the harness's reference BIGNUM
X25519 ladder: X-Wing 2,361 / 1,268 µs, RFC 10024 2,497 / 1,196 µs, pack
2,401 / 1,218 µs (means; medians 2,314 / 1,199 µs, 2,315 / 1,178 µs,
2,320 / 1,201 µs). The three combiners are indistinguishable in speed at
this resolution — the combiner choice is a standards and properties
decision, not a performance decision. Hybrid timings are
reference-implementation figures, not production figures.

## F-10 — MEDIUM (SPEC-DERIVED): the FIPS 203 section 7.3 length check must live in the application

FIPS 203 section 7.3 requires a ciphertext-length check on every
decapsulation. The liboqs C API takes a fixed-length ciphertext buffer
with no length parameter, so a short ciphertext cannot even be
represented at that layer, and the harness records truncated-ciphertext
handling as UNSUPPORTED (`outputs/harness.log:27-28`). A wrapper that
passes unchecked buffers to decapsulation is relying on the caller, not
on the library, for input validation. Any deployment must implement the
section 7.3 checks (ciphertext length, key length, hash check) before
calling decapsulation.

## F-11 — LOW (SPEC-DERIVED): ML-KEM alone lacks the binding properties X-Wing provides

draft-11 section 6.1 states X-Wing satisfies MAL-BIND-K-PK and
MAL-BIND-K-CT (and, by implication, the derived LEAK/HON binding
properties), while ML-KEM on its own does not achieve MAL-BIND-K-PK.
Protocols that rely on a shared secret being bound to a specific public
key or ciphertext should prefer the hybrid over bare ML-KEM.

## Unsupported claims (explicitly not supported by this pack)

- **U-01** — Behaviour on a truncated ciphertext (see F-10; untestable at
  the liboqs C API layer).
- **U-02** — Constant-time behaviour of any decapsulation implementation
  (see F-04; coarse timing only).
- **U-03** — Production performance of any hybrid KEM (see F-09;
  reference BIGNUM ladder).
- **U-04** — Conformance of the harness X-Wing combiner to draft-11 test
  vectors (see F-07; none published).
- **U-05** — Exploitability of a failure oracle against a deployed
  service (no deployed ML-KEM service exists in postfiatd; lab result
  only).
- **U-06** — The FIPS 203 decapsulation failure rates (`2^-138.8`,
  `2^-164.8`, `2^-174.8`) as measured values. They are specification
  values; measuring them would require ~2^139 trials and is infeasible.
- **U-07** — Security of the pack combiner (lab control only; not
  analysed, not standardised, must not be deployed).
