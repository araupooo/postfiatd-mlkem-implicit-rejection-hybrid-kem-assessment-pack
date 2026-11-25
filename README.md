# ML-KEM Implicit-Rejection and Hybrid-KEM Assessment

An assessment of ML-KEM (FIPS 203) implicit rejection, measured on the
liboqs 0.14.0 reference implementation, against a pinned postfiatd source
revision. It covers decapsulation failures, failure-oracle exposure,
key-reuse risks, and an X-Wing versus classical-plus-ML-KEM comparison.

## Pinned revisions

| Component | Revision | Verified |
|---|---|---|
| postfiatd (`postfiatorg/postfiatd`, `main`) | `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, merge PR #50) | local clone HEAD equals the GitHub API commit SHA |
| liboqs | tag `0.14.0`, commit `94b421ebb82405c843dba4e9aa521a56ee5a333d` (2025-07-10) | local clone HEAD equals the GitHub API commit SHA |

## Headline results (measured)

- **postfiatd contains no ML-KEM/KEM code.** Zero whole-word matches for
  `KEM`, `decapsulat*`, `encapsulat*`, `Kyber`, `ML-KEM` in `src/` and
  `include/`; the only "kem" substring hits are `makeMemberName` /
  `makeMptID` false positives. The only key types are `secp256k1` and
  `ed25519` (`include/xrpl/protocol/KeyType.h:28-31`). There is no
  decapsulation-failure handling in postfiatd to trace. See
  `outputs/source-trace.log`.
- **Implicit rejection confirmed, no error is ever returned.** For all three
  parameter sets, every well-formed-length invalid ciphertext — 3 bit-flips,
  32 random, 1 all-zero each — decapsulated with return code `OQS_SUCCESS`
  to a 32-byte secret different from the reference secret. All 32 random
  rejected outputs per parameter set were distinct.
- **Sizes match FIPS 203 Table 3** for all three parameter sets.
- **Benchmarks** (mean, n=200, single-threaded, this VM): ML-KEM-512
  encaps 9.18 µs / decaps 12.11 µs; ML-KEM-768 encaps 14.86 µs / decaps
  18.70 µs; ML-KEM-1024 encaps 19.04 µs / decaps 25.38 µs.
- **Coarse timing** (ML-KEM-768 decaps, n=1000 each): valid mean 19.170 µs,
  invalid mean 18.832 µs, median identical at 18.297 µs, ratio 0.9824 — no
  observable timing signal at wall-clock resolution. This is not a
  constant-time proof.
- **Key reuse**: 100 encaps/decaps under one ML-KEM-768 keypair all matched;
  all 100 ciphertexts distinct; replay of an old ciphertext decapsulates
  successfully; decapsulation under the wrong key returns success with a
  wrong secret (silent key confusion).
- **Hybrids** (ML-KEM-768 + X25519, n=200): X-Wing, RFC 10024 concatenation,
  and the pack combiner all round-trip. Measured encaps ~2.36–2.50 ms and
  decaps ~1.20–1.27 ms are dominated by the harness's reference BIGNUM
  X25519 ladder, not by ML-KEM — they are reference-implementation figures,
  not production figures. The distinguishing measurement: an all-zero
  X25519 ciphertext part decapsulates to a value under X-Wing (draft-11)
  and under the pack combiner, but the RFC 10024 combiner aborts, as
  RFC 10024 section 4.3 requires.

## Reproduce

```sh
./run_all.sh [bench_n] [timing_n]
```

Defaults `200 1000`. The script clones liboqs 0.14.0 and postfiatd at the
pinned commits, builds liboqs and the harness, runs the harness, runs the
source trace, regenerates `SHA256SUMS`, and verifies digests. Network is
needed once for the clones. Exit code 0 means every check passed, including
`verify_digests.sh`.

## Layout

| Path | Contents |
|---|---|
| `src/mlkem_harness.c` | The harness (C, liboqs + OpenSSL SHA3-256 + in-harness RFC 7748 X25519) |
| `scripts/` | `trace_postfiatd.sh`, `make_sha256sums.sh`, `verify_digests.sh` |
| `configs/bench-params.json` | Benchmark parameters used for the shipped run |
| `docs/methodology.md` | Scope, threat boundaries, evidence labels, harness design, deviations |
| `docs/citations.md` | Primary sources, exact sections, retrieval dates |
| `docs/findings.md` | Ranked findings with severity scores |
| `docs/remediation.md` | Prioritized operator remediation (P0–P3) |
| `docs/decision-memo.md` | Hybrid-KEM decision memo |
| `docs/claim-index.md` | Every claim traced to script, raw output line, digest, source |
| `docs/environment.md` | Environment record and pinned revisions |
| `outputs/harness.log` | Unedited harness output (101 lines) |
| `outputs/source-trace.log` | Unedited source-trace output (164 lines) |
| `outputs/reproduce.log` | Fresh-clone rerun log |
| `findings.json` | Machine-readable findings |
| `run-manifest.json` | Run counts and totals |
| `SHA256SUMS` | Full 64-char SHA-256 digests of every pack file |

## Evidence labels

- **MEASURED** — produced by the harness in this pack and recorded in
  `outputs/harness.log`.
- **SPEC-DERIVED** — taken from a cited primary source (FIPS 203, RFC 7748,
  RFC 10024, draft-11); labelled with the source, not measured.
- **SIMULATED** — produced by the harness but standing in for a deployment
  that does not exist here (the hybrid keypairs use independent keypairs
  because liboqs does not expose `ML-KEM.KeyGen_internal`; see
  `docs/methodology.md`).
- **UNSUPPORTED** — claimed by no evidence in this pack; listed in
  `docs/findings.md` so nothing is silently assumed.

## Limits, stated plainly

- postfiatd has no ML-KEM code, so no deployed decapsulation-failure
  behaviour could be observed; all failure behaviour was measured on liboqs.
- liboqs 0.14.0 does not ship X-Wing, and its C API cannot represent a
  truncated ciphertext, so truncated-ciphertext handling is unsupported.
- The coarse timing comparison is not a constant-time proof.
- Hybrid timings use a reference BIGNUM X25519 ladder, not a production
  implementation.
- The X-Wing draft has no published test vectors (Appendix C is TODO), so
  the combiner was validated by round-trip and by the SHA3-256 / RFC 7748
  self-tests, not against draft vectors.
