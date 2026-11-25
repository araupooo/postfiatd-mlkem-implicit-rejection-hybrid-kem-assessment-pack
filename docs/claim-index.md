# Claim-to-evidence index

Every substantive claim in this pack, traced to the script that produced
it, the raw output file and line, the digest entry, and the primary
source. Line numbers are for the shipped `outputs/harness.log` (101
lines) and `outputs/source-trace.log` (164 lines); verify them with
`grep -n`. All files are covered by `SHA256SUMS` (verify with
`./scripts/verify_digests.sh`).

## Pinned revisions

| Claim | Evidence |
|---|---|
| postfiatd HEAD is `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10), matching the GitHub API | `outputs/source-trace.log:2`; `docs/citations.md` (postfiatd) |
| liboqs 0.14.0 commit is `94b421ebb82405c843dba4e9aa521a56ee5a333d`, matching the GitHub API | `outputs/harness.log:2` (`ENV liboqs=0.14.0`); `run_all.sh` commit check; `docs/citations.md` (liboqs) |
| postfiatd HEAD is unchanged from the earlier 2026-11-25 pin | `docs/environment.md` |

## Source trace (postfiatd)

| Claim | Evidence |
|---|---|
| No whole-word `KEM` / `decapsulat*` / `encapsulat*` / `Kyber` / `ML-KEM` matches in `src/` or `include/` | `scripts/trace_postfiatd.sh`; `outputs/source-trace.log:4` |
| Remaining `kem` substring hits are only `makeMemberName` / `makeMptID` false positives | `outputs/source-trace.log:6-134` |
| Only key types are `secp256k1` and `ed25519` | `include/xrpl/protocol/KeyType.h:28-31`, quoted in `outputs/source-trace.log:135-148` and `docs/citations.md` |
| Key-type use sites: `PublicKey.cpp:229,232`, `SecretKey.cpp:263,269` | `outputs/source-trace.log:149-162` |
| No KEM-like filenames in the tree | `outputs/source-trace.log:163-164` |

## Sizes and self-tests

| Claim | Evidence |
|---|---|
| ML-KEM sizes match FIPS 203 Table 3 for all three parameter sets | `src/mlkem_harness.c` (Section A); `outputs/harness.log:10-11, 31-32, 61-62` |
| SHA3-256 self-test passes (empty-string known value) | `outputs/harness.log:4` |
| RFC 7748 §5.2 X25519 vectors 1 and 2 pass | `outputs/harness.log:5-6` |
| `X25519(sk, 0) = 0` | `outputs/harness.log:7` |
| liboqs 0.14.0 does not ship X-Wing | `docs/citations.md` (liboqs, `src/kem/` inventory); `outputs/harness.log:82` (keygen note) |

## Benchmarks (MEASURED, n=200)

| Claim | Evidence |
|---|---|
| ML-KEM-512 keygen / encaps / decaps means 8.604 / 9.176 / 12.110 µs | `outputs/harness.log:12-14` |
| ML-KEM-768 keygen / encaps / decaps means 14.220 / 14.860 / 18.699 µs | `outputs/harness.log:33-35` |
| ML-KEM-1024 keygen / encaps / decaps means 18.610 / 19.044 / 25.376 µs | `outputs/harness.log:63-65` |
| Round-trip encaps/decaps match for all three parameter sets | `outputs/harness.log:15, 36, 66` |

## Failure injection (MEASURED)

| Claim | Evidence |
|---|---|
| Bit-flipped ciphertexts return `OQS_SUCCESS` with a different secret (3 per parameter set) | `outputs/harness.log:18-20, 39-41, 69-71` |
| 32 random ciphertexts per parameter set: all `OQS_SUCCESS`, 32/32 distinct rejected secrets, none equal to the reference | `outputs/harness.log:21-24, 42-45, 72-75` |
| All-zero ciphertext returns `OQS_SUCCESS` with a different secret | `outputs/harness.log:25, 46, 76` |
| Truncated-ciphertext handling is UNSUPPORTED at the liboqs C API layer | `outputs/harness.log:27-28, 48-49, 78-79` |

## Timing (MEASURED, coarse only)

| Claim | Evidence |
|---|---|
| Valid decaps mean 19.170 µs, invalid 18.832 µs, medians both 18.297 µs, ratio 0.9824 (n=1000 each) | `outputs/harness.log:51-53` |
| The comparison is wall-clock only, not a constant-time proof | `outputs/harness.log:54` |

## Key reuse (MEASURED)

| Claim | Evidence |
|---|---|
| 100 encaps/decaps under one keypair all match; all 100 ciphertexts distinct | `outputs/harness.log:56` |
| Replay of the first ciphertext decapsulates successfully | `outputs/harness.log:57` |
| Decapsulation under the wrong key returns success with a wrong secret | `outputs/harness.log:58` |

## Hybrids (MEASURED)

| Claim | Evidence |
|---|---|
| X-Wing / RFC 10024 / pack combiners all round-trip | `outputs/harness.log:83, 89, 95` |
| Hybrid sizes: pk 1216, ct 1120, ss 32 / 64 / 32 | `outputs/harness.log:81` |
| Hybrid keypairs use independent keypairs, not draft §5.2 seed expansion (labelled deviation) | `outputs/harness.log:82` |
| Hybrid encaps means 2361 / 2497 / 2401 µs; decaps means 1268 / 1196 / 1218 µs (n=200) | `outputs/harness.log:84-85, 90-91, 96-97` |
| Bit-flip in either ciphertext part: different secret, no error, for all three combiners | `outputs/harness.log:86-87, 92-93, 98-99` |
| All-zero X25519 part: X-Wing rc=0, RFC 10024 rc=-2 (abort), pack rc=0 | `outputs/harness.log:88, 94, 100` |

## Spec-derived claims

| Claim | Primary source |
|---|---|
| Implicit rejection: on mismatch, `K' <- J(z\|\|c)`; the flag is secret and must be destroyed, never returned | FIPS 203 §6.3, Alg. 18 |
| Decaps always outputs a 32-byte secret after input checks | FIPS 203 §7.3, Alg. 21 |
| Decapsulation failure rates `2^-138.8` / `2^-164.8` / `2^-174.8` | FIPS 203 §3.2, Table 1 |
| Parameter-set sizes | FIPS 203 §8, Table 3 |
| X-Wing sizes, combiner, key generation, decapsulation | draft-11 §§5.1–5.5 |
| X-Wing binding properties; ML-KEM lacks MAL-BIND-K-PK | draft-11 §6.1 |
| RFC 10024 shared secret is the concatenation; all-zero X25519 aborts | RFC 10024 §4.3 |
| X-Wing is a draft (expires 27 Mar 2027); RFC 10024 is Standards Track | draft-11 header; RFC 10024 header |
| X25519 ladder, masking, test vectors | RFC 7748 §§5, 5.2 |

## Unsupported claims

| Claim | Status |
|---|---|
| Truncated-ciphertext behaviour | U-01 in `docs/findings.md`; `outputs/harness.log:27-28` |
| Constant-time behaviour | U-02; `outputs/harness.log:54` |
| Production hybrid performance | U-03; `outputs/harness.log:84-85, 90-91, 96-97` (reference ladder) |
| Draft-11 test-vector conformance | U-04; draft-11 Appendix C is TODO |
| Failure-oracle exploitability in deployment | U-05 |
| Measured decapsulation failure rates | U-06 |
| Security of the pack combiner | U-07 |
