# Hybrid-KEM decision memo

## Recommendation

- **For TLS 1.3: adopt RFC 10024 X25519MLKEM768.** It is a published
  standard (Standards Track, August 2026), has an IANA-registered code
  point, mandates the all-zero X25519 shared-secret abort, and is the
  hybrid the ecosystem is converging on.
- **For general-purpose (non-TLS) hybrid KEM use: adopt X-Wing
  draft-connolly-cfrg-xwing-kem-11, pinned to draft-11, with the all-zero
  X25519 check added.** It is the best-documented general-purpose
  construction, has a simpler combiner than the TLS concatenation
  approach, and provides stronger binding properties than bare ML-KEM.
  Re-validate when the draft is published or superseded.
- **Do not deploy the pack combiner.** It exists only as a labelled
  control in this assessment.

## Comparison (measured where stated, otherwise spec-derived)

| Property | X-Wing (draft-11) | RFC 10024 X25519MLKEM768 | Pack combiner |
|---|---|---|---|
| Status | Internet-Draft, expires 27 Mar 2027 | RFC, Standards Track, Aug 2026 | Lab control, not standardised |
| Components | ML-KEM-768 + X25519 | ML-KEM-768 + X25519 | ML-KEM-768 + X25519 |
| Public key | 1216 bytes | 1216 bytes | 1216 bytes |
| Ciphertext | 1120 bytes | 1120 bytes | 1120 bytes |
| Shared secret | 32 bytes | 64 bytes (concatenation) | 32 bytes |
| Combiner | SHA3-256(ss_M \|\| ss_X \|\| ct_X \|\| pk_X \|\| label) | ss_M \|\| ss_X | SHA3-256(domain \|\| ss_M \|\| ss_X \|\| ct_X \|\| pk_X) |
| All-zero X25519 check | Not specified (measured: returns a value) | Mandatory abort (measured: aborts) | Not specified (measured: returns a value) |
| Binding properties | MAL-BIND-K-PK, MAL-BIND-K-CT (draft §6.1) | Not stated in RFC 10024 | Not analysed |
| Encaps, mean (measured, n=200) | 2,361 µs | 2,497 µs | 2,401 µs |
| Decaps, mean (measured, n=200) | 1,268 µs | 1,196 µs | 1,218 µs |
| Encaps, median (measured) | 2,314 µs | 2,315 µs | 2,320 µs |
| Decaps, median (measured) | 1,199 µs | 1,178 µs | 1,201 µs |
| Failure behaviour (measured) | Bit-flip in either part: different secret, no error | Same | Same |

## Why this recommendation

1. **Standardization.** RFC 10024 is finished and registered; draft-11
   is not. Where a standard exists for the use case (TLS), use it.
2. **Failure behaviour.** The one measured difference between the
   constructions is the all-zero X25519 case: RFC 10024 aborts, X-Wing
   silently returns a value. The abort is the safer default, and any
   X-Wing deployment must add it (remediation R-03).
3. **Binding.** X-Wing's combiner binds the output to the X25519
   ciphertext and public key, and the draft claims MAL-BIND-K-PK /
   MAL-BIND-K-CT, which bare ML-KEM lacks. The RFC 10024 concatenation
   does not mix the ciphertext or public key into the output. For
   non-TLS protocols that rely on binding, X-Wing is the better shape.
4. **Performance is not a differentiator.** All three combiners measure
   within noise of each other (medians within 6 µs on encaps, 23 µs on
   decaps), and all three are dominated by the reference X25519 ladder
   (~1.2 ms per ladder call), not by the combiner. The choice should be
   made on standards status and properties, not speed.
5. **Availability.** Neither construction ships in liboqs 0.14.0 as a
   single KEM (X-Wing is absent; the RFC 10024 hybrids live in
   oqs-provider/OpenSSL, not liboqs). Either choice requires assembling
   the combiner from ML-KEM-768 and X25519 primitives, as this pack's
   harness does.

## Conditions

- Pin the draft version (draft-11) and the library versions; re-validate
  on any change.
- Add the all-zero X25519 check to any X-Wing deployment.
- Apply remediation R-01, R-02, R-05, R-06 regardless of combiner choice:
  the implicit-rejection properties of the underlying ML-KEM are the same
  in all three.
- Do not treat the hybrid timings in this pack as production figures;
  they use a reference BIGNUM X25519 ladder (see `docs/methodology.md`).
