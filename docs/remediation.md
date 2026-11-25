# Operator remediation

Prioritized for an operator introducing ML-KEM or a hybrid KEM. Each item
names the finding it addresses.

## P0 — before any deployment

- **R-01 (F-02, F-05). Never treat decapsulation success as authentication.**
  Implicit rejection returns a 32-byte value for every well-formed-length
  ciphertext. Bind the shared secret to the session with a KDF over the
  full transcript (ciphertext, public keys, session identifiers) and
  require an authenticated message (MAC or signature) before trusting
  anything derived from it.
- **R-02 (F-10). Implement the FIPS 203 section 7.3 input checks in the
  application wrapper before calling decapsulation**: ciphertext length,
  decapsulation-key length, and the key-hash check. Do not rely on the
  library to reject malformed input.
- **R-03 (F-06). Add the all-zero X25519 shared-secret abort to any
  hybrid decapsulation.** Reject (do not derive from) an all-zero
  X25519 shared secret, as RFC 10024 section 4.3 requires for TLS. This
  applies in particular to any X-Wing deployment, whose draft specifies
  no such check.

## P1 — at deployment

- **R-04 (F-07, F-09). Use the standardized hybrid where it exists.**
  For TLS 1.3, use RFC 10024 X25519MLKEM768. For non-TLS use, X-Wing
  draft-11 is acceptable only pinned to draft-11 with R-03 applied and
  with a plan to re-validate when the draft is published or superseded.
  Do not deploy the pack combiner (lab control only).
- **R-05 (F-02, F-03). Monitor for implicit-rejection events.** The only
  observable signal of a rejected decapsulation is a downstream
  authentication failure. Count session-key derivations that fail
  authentication, alert on a rate above baseline, and treat a spike as a
  possible failure-oracle probe. Log counts, never the rejected secrets.
- **R-06 (F-05). Treat shared secrets as single-use and session-bound.**
  Never reuse a shared secret across sessions; rotate keypairs on a
  schedule; assume a replayed ciphertext replays the session key and
  design the protocol so replay alone gains nothing (nonces, transcript
  binding).
- **R-07 (F-01). Do not assume postfiatd handles any of this.** The pinned
  tree has no KEM code. ML-KEM integration is a new subsystem: new key
  types, new storage, new RPC surfaces, and new tests — not a
  configuration change.

## P2 — before production traffic

- **R-08 (F-04). Commission a dedicated side-channel evaluation** of the
  chosen decapsulation implementation (constant-time review, ideally with
  tooling). The coarse wall-clock comparison in this pack is not
  sufficient evidence.
- **R-09 (F-07, F-08). Track the X-Wing draft and the library.**
  Re-validate when draft-11 is published as an RFC or replaced, when
  test vectors appear in Appendix C, and when liboqs ships X-Wing or
  exposes `KeyGen_internal`. Re-run this pack's harness against the
  production library version and implementation before going live.

## P3 — ongoing

- **R-10 (F-11). Prefer the hybrid where binding properties matter.**
  If the protocol relies on a shared secret being bound to a specific
  public key or ciphertext, use the hybrid (X-Wing or RFC 10024) rather
  than bare ML-KEM.
- **R-11 (F-09). Re-benchmark on production hardware.** The figures in
  this pack are from a shared-vCPU VM with a reference X25519
  implementation; size provisioning (ML-KEM-768: 1184-byte public key,
  1088-byte ciphertext; X-Wing: 1216-byte public key, 1120-byte
  ciphertext) should be re-checked against production constraints.
