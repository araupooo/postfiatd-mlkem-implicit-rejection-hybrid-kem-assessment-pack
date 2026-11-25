# Methodology

## Scope

This pack assesses ML-KEM (FIPS 203) implicit rejection:

1. What happens when decapsulation is given an invalid ciphertext
   (bit-flipped, random, all-zero, truncated).
2. Whether an attacker observing decapsulation outputs can learn anything
   (failure-oracle exposure), including coarse timing.
3. What key reuse means for ML-KEM in practice.
4. How X-Wing (draft-connolly-cfrg-xwing-kem-11) compares with a
   classical-plus-ML-KEM combiner (RFC 10024 concatenation) and with a
   pack-defined combiner, on sizes, speed, and failure behaviour.

The pinned postfiatd revision is examined for ML-KEM / KEM /
decapsulation code and for its key types, so the assessment is grounded in
what the code actually contains.

## Threat boundaries

- **In scope**: the ML-KEM algorithms as implemented by liboqs 0.14.0;
  the X-Wing and RFC 10024 combiners as specified; the postfiatd source
  tree at the pinned revision.
- **Out of scope**: any deployed postfiatd ML-KEM service (none exists in
  the pinned tree); network-level attacks; side-channel attacks beyond a
  coarse wall-clock comparison; the security of X25519 or SHA3 themselves;
  production performance of any hybrid (the harness X25519 is a reference
  implementation).
- **Assumed attacker**: can submit arbitrary ciphertexts for decapsulation
  under a fixed key and observe the returned shared secret (or the
  downstream session-key derivation failing) and the time taken. The
  attacker does not know the decapsulation key or the implicit-rejection
  value `z`.

## Evidence labels

| Label | Meaning |
|---|---|
| MEASURED | Produced by the harness in this pack; recorded in `outputs/harness.log` with a line number in `docs/claim-index.md`. |
| SPEC-DERIVED | Taken from a cited primary source; the source and section are given, and the claim is not presented as measured. |
| SIMULATED | Produced by the harness, but standing in for a deployment that does not exist here (hybrid key generation; see "Deviations"). |
| UNSUPPORTED | No evidence in this pack supports the claim; listed explicitly in `docs/findings.md`. |

## Harness design

`src/mlkem_harness.c` (C, single-threaded) uses the liboqs `OQS_KEM` API
for ML-KEM-512/768/1024, OpenSSL for SHA3-256 and SHA-256, and an
in-harness RFC 7748 Montgomery ladder (BIGNUM arithmetic) for X25519.
Raw keys and raw shared secrets are never printed; shared secrets are
logged only as full 64-character SHA-256 hex digests.

Sections:

- **A** — parameter-set sizes, checked against FIPS 203 Table 3.
- **B** — keygen / encaps / decaps benchmarks, n=200, wall clock
  (`clock_gettime(CLOCK_MONOTONIC)`), mean / median / min / max / stdev /
  ops-per-second.
- **C** — failure injection per parameter set: bit flips at the first,
  middle, and last ciphertext byte; 32 random ciphertexts with a
  distinctness count; one all-zero ciphertext; truncated-ciphertext
  handling (see "Deviations").
- **D** — coarse timing: n=1000 decapsulations of a valid ciphertext vs
  n=1000 of a bit-flipped ciphertext (ML-KEM-768), with means, medians,
  and ratio. Wall-clock only; not a constant-time proof.
- **E** — key reuse (ML-KEM-768): 100 encaps/decaps pairs under one
  keypair; replay of the first ciphertext; decapsulation of a ciphertext
  under the wrong decapsulation key.
- **F** — hybrids (ML-KEM-768 + X25519), three combiners, n=200 each:
  X-Wing (draft-11 section 5.3), RFC 10024 section 4.3 concatenation,
  and the pack combiner (below). Each combiner is tested for round-trip,
  benchmarked, and subjected to bit-flips in each ciphertext part and to
  an all-zero X25519 ciphertext part.

Self-tests run before any measurement and abort the run's pass status on
failure: SHA3-256 of the empty string against its known value, both
RFC 7748 section 5.2 X25519 test vectors, and `X25519(sk, 0) = 0`.

## The three combiners

1. **X-Wing** (draft-connolly-cfrg-xwing-kem-11, section 5.3):
   `SHA3-256(ss_M || ss_X || ct_X || pk_X || label)` with label bytes
   `5c2e2f2f5e5c`, 32-byte output. Encapsulation key 1216 bytes,
   ciphertext 1120 bytes, shared secret 32 bytes (draft section 5.1).
2. **RFC 10024** (RFC 10024, section 4.3): shared secret is the
   concatenation `ss_M || ss_X`, 64 bytes; the all-zero X25519 shared
   secret must abort the connection. Encapsulation key 1216 bytes,
   ciphertext 1120 bytes (same components as X-Wing).
3. **Pack combiner** (this pack's own construction, not standardized):
   `SHA3-256("MLKEM768-X25519-PACK-v1" || ss_M || ss_X || ct_X || pk_X)`,
   32-byte output. Included only as a labelled control to show that the
   measured failure behaviour does not depend on the choice of combiner
   label; it must not be deployed.

## Deviations (labelled, not hidden)

1. **Hybrid key generation.** draft-11 section 5.2 derives the ML-KEM-768
   keypair deterministically from a 32-byte seed via SHAKE256
   (`expandDecapsulationKey`, using `ML-KEM.KeyGen_internal`). liboqs
   0.14.0 does not expose `KeyGen_internal`, so the harness generates an
   independent liboqs ML-KEM-768 keypair and an independent X25519
   keypair. The combiner, encapsulation, and decapsulation steps follow
   the cited specifications exactly. The harness prints this as
   `RESULT hybrid keygen_note=...` (`outputs/harness.log:82`).
2. **X25519 implementation.** OpenSSL EVP refuses the all-zero peer
   public key, which would mask the draft-defined behaviour under test
   (`X25519(sk, 0) = 0`). The harness therefore implements the RFC 7748
   section 5 ladder itself (BIGNUM arithmetic, validated against both
   section 5.2 test vectors). It is a reference implementation: not
   constant-time, not for production. Hybrid timings are therefore
   reference-implementation figures; the ML-KEM timings are not affected.
3. **Truncated ciphertexts.** The liboqs `OQS_KEM_decaps` C API takes a
   fixed-length ciphertext buffer with no length parameter, so a short
   ciphertext cannot be represented at this API layer. Truncated-input
   behaviour is UNSUPPORTED here; the FIPS 203 section 7.3 ciphertext
   length check must live in the application wrapper (see F-10).
4. **No draft test vectors.** draft-11 Appendix C is marked TODO, so the
   X-Wing combiner could not be validated against published vectors. It
   was validated by round-trip, by the SHA3-256 self-test, and by the
   RFC 7748 vector self-tests.

## Reproduce

`./run_all.sh [bench_n] [timing_n]` (defaults `200 1000`). The script
pins liboqs 0.14.0 and postfiatd by full commit SHA and fails if either
HEAD has moved. `outputs/harness.log` is the unedited stdout of the
harness; `outputs/source-trace.log` is the unedited stdout of
`scripts/trace_postfiatd.sh`.
