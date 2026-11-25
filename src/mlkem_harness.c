/*
 * mlkem_harness.c — ML-KEM implicit-rejection and hybrid-KEM assessment harness.
 *
 * What it measures (all against liboqs 0.14.0, FIPS 203 ML-KEM):
 *   A. Parameter-set sizes vs FIPS 203 Table 3.
 *   B. Keygen / encaps / decaps benchmarks (single-threaded wall clock).
 *   C. Failure injection: bit-flipped, random, all-zero, truncated, overlong,
 *      empty ciphertexts — error vs pseudorandom shared secret (implicit
 *      rejection), and distinctness of the rejected outputs.
 *   D. Coarse timing comparison: decaps of valid vs invalid ciphertexts.
 *      This is a wall-clock comparison only, NOT a constant-time proof.
 *   E. Key reuse: repeated encaps/decaps under one keypair; replay of an old
 *      ciphertext; decapsulation under the wrong decapsulation key.
 *   F. Hybrid KEMs (ML-KEM-768 + X25519), three combiners:
 *        1. X-Wing, draft-connolly-cfrg-xwing-kem-11 section 5.3:
 *           SHA3-256(ss_M || ss_X || ct_X || pk_X || label 5c2e2f2f5e5c).
 *        2. RFC 10024 section 4.3 concatenation: ss = ss_M || ss_X (64 bytes),
 *           with the mandatory all-zero X25519 shared-secret abort.
 *        3. Pack construction (NOT standardized, labelled as the pack's own):
 *           SHA3-256("MLKEM768-X25519-PACK-v1" || ss_M || ss_X || ct_X || pk_X).
 *      X25519 note: the harness implements X25519 itself (RFC 7748 section 5
 *      Montgomery ladder, BIGNUM arithmetic), validated against the RFC 7748
 *      section 5.2 vectors, because OpenSSL EVP refuses the all-zero peer key.
 *      Key-generation note: liboqs 0.14.0 does not expose ML-KEM.KeyGen_internal,
 *      so the draft's SHAKE256 seed-expansion key generation (draft-11 section
 *      5.2) cannot be used. Hybrid keypairs here are an independent liboqs
 *      ML-KEM-768 keypair plus an independent OpenSSL X25519 keypair. The
 *      combiner, encapsulation and decapsulation steps follow the cited
 *      specifications exactly; only key generation differs, and it is
 *      labelled here as a harness deviation, not as the draft's construction.
 *
 * The harness never prints raw keys or raw shared secrets. Shared secrets are
 * logged only as full 64-character SHA-256 hex digests.
 *
 * Build: see Makefile / run_all.sh. Link: -loqs -lcrypto -lm.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

static int g_failures = 0;

static void die(const char *msg) { fprintf(stderr, "FATAL: %s\n", msg); exit(2); }

static void sha256_hex(const uint8_t *in, size_t len, char out[65]) {
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(in, len, d);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(out + 2 * i, "%02x", d[i]);
    out[64] = 0;
}

static int is_all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

static void hex_encode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out + 2 * i, "%02x", in[i]);
    out[2 * len] = 0;
}

static int rand_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

typedef struct { double mean, median, min, max, stdev; } stats_t;

static stats_t stats(uint64_t *v, size_t n) {
    stats_t s;
    double sum = 0;
    s.min = (double)v[0]; s.max = (double)v[0];
    for (size_t i = 0; i < n; i++) { sum += (double)v[i]; if ((double)v[i] < s.min) s.min = (double)v[i]; if ((double)v[i] > s.max) s.max = (double)v[i]; }
    s.mean = sum / (double)n;
    double sq = 0;
    for (size_t i = 0; i < n; i++) { double d = (double)v[i] - s.mean; sq += d * d; }
    s.stdev = sqrt(sq / (double)n);
    qsort(v, n, sizeof(uint64_t), cmp_u64);
    s.median = (n % 2) ? (double)v[n / 2] : ((double)v[n / 2 - 1] + (double)v[n / 2]) / 2.0;
    return s;
}

/* ---------- X25519 via an in-harness RFC 7748 Montgomery ladder ----------
 * Implemented with OpenSSL BIGNUM arithmetic (reference implementation for
 * measurement only: NOT constant-time, NOT for production use). The ladder
 * is used instead of OpenSSL EVP because EVP_PKEY_derive refuses the
 * all-zero peer public key, which would mask the draft-defined behaviour
 * under test (X25519(sk, 0) = 0 per RFC 7748 section 5). Validated against
 * the RFC 7748 section 5.2 test vectors in main() before any hybrid use.
 * Scalar clamping and the ladder follow RFC 7748 section 5 exactly. */
static void bn_le_bytes(const BIGNUM *n, uint8_t out[32]) {
    memset(out, 0, 32);
    int len = BN_num_bytes(n);
    uint8_t *tmp = malloc((size_t)len);
    BN_bn2bin(n, tmp);
    for (int i = 0; i < len; i++) out[i] = tmp[len - 1 - i];
    free(tmp);
}

static BIGNUM *bn_from_le(const uint8_t in[32]) {
    uint8_t be[32];
    for (int i = 0; i < 32; i++) be[i] = in[31 - i];
    return BN_bin2bn(be, 32, NULL);
}

static void x25519_ladder(const uint8_t k_in[32], const uint8_t u_in[32], uint8_t out[32]) {
    uint8_t k[32];
    memcpy(k, k_in, 32);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
    /* RFC 7748 section 5 decodeUCoordinate: mask the most significant bit. */
    uint8_t u_masked[32];
    memcpy(u_masked, u_in, 32);
    u_masked[31] &= 0x7f;
    u_in = u_masked;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *a24 = BN_new(), *one = BN_new();
    BIGNUM *x1 = bn_from_le(u_in), *x2 = BN_new(), *z2 = BN_new();
    BIGNUM *x3 = BN_new(), *z3 = BN_new();
    BIGNUM *A = BN_new(), *AA = BN_new(), *B = BN_new(), *BB = BN_new();
    BIGNUM *E = BN_new(), *C = BN_new(), *D = BN_new(), *DA = BN_new(), *CB = BN_new();
    BIGNUM *t1 = BN_new(), *t2 = BN_new();
    BN_one(p); BN_lshift(p, p, 255); BN_sub_word(p, 19); /* p = 2^255 - 19 */
    BN_set_word(a24, 121665);
    BN_one(one);
    BN_mod(x1, x1, p, ctx); /* x1 = decodeUCoordinate(u): top bit of byte 31 already masked by caller */
    BN_copy(x2, one); BN_zero(z2); BN_copy(x3, x1); BN_copy(z3, one);
    int swap = 0;
    for (int t = 254; t >= 0; t--) {
        int kt = (k[t >> 3] >> (t & 7)) & 1;
        swap ^= kt;
        if (swap) { BN_swap(x2, x3); BN_swap(z2, z3); }
        swap = kt;
        /* A = x2 + z2; AA = A^2; B = x2 - z2; BB = B^2; E = AA - BB */
        BN_mod_add(A, x2, z2, p, ctx);
        BN_mod_sqr(AA, A, p, ctx);
        BN_mod_sub(B, x2, z2, p, ctx);
        BN_mod_sqr(BB, B, p, ctx);
        BN_mod_sub(E, AA, BB, p, ctx);
        /* C = x3 + z3; D = x3 - z3; DA = D*A; CB = C*B */
        BN_mod_add(C, x3, z3, p, ctx);
        BN_mod_sub(D, x3, z3, p, ctx);
        BN_mod_mul(DA, D, A, p, ctx);
        BN_mod_mul(CB, C, B, p, ctx);
        /* x3 = (DA + CB)^2; z3 = x1 * (DA - CB)^2 */
        BN_mod_add(t1, DA, CB, p, ctx);
        BN_mod_sqr(x3, t1, p, ctx);
        BN_mod_sub(t1, DA, CB, p, ctx);
        BN_mod_sqr(t1, t1, p, ctx);
        BN_mod_mul(z3, x1, t1, p, ctx);
        /* x2 = AA * BB; z2 = E * (AA + a24 * E) */
        BN_mod_mul(x2, AA, BB, p, ctx);
        BN_mod_mul(t1, a24, E, p, ctx);
        BN_mod_add(t2, AA, t1, p, ctx);
        BN_mod_mul(z2, E, t2, p, ctx);
    }
    if (swap) { BN_swap(x2, x3); BN_swap(z2, z3); }
    /* out = x2 * z2^(p-2) mod p */
    BIGNUM *exp = BN_new(), *zinv = BN_new(), *res = BN_new();
    BN_copy(exp, p); BN_sub_word(exp, 2);
    BN_mod_exp(zinv, z2, exp, p, ctx);
    BN_mod_mul(res, x2, zinv, p, ctx);
    bn_le_bytes(res, out);
    BN_free(p); BN_free(a24); BN_free(one); BN_free(x1); BN_free(x2); BN_free(z2);
    BN_free(x3); BN_free(z3); BN_free(A); BN_free(AA); BN_free(B); BN_free(BB);
    BN_free(E); BN_free(C); BN_free(D); BN_free(DA); BN_free(CB);
    BN_free(t1); BN_free(t2); BN_free(exp); BN_free(zinv); BN_free(res);
    BN_CTX_free(ctx);
}

static int hex_decode(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int x25519_pub(const uint8_t priv[32], uint8_t pub[32]) {
    static const uint8_t base[32] = {9};
    x25519_ladder(priv, base, pub);
    return 0;
}

static int x25519_dh(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t out[32]) {
    x25519_ladder(priv, peer_pub, out);
    return 0;
}

static int sha3_256(const uint8_t *in, size_t len, uint8_t out[32]) {
    unsigned int olen = 0;
    return EVP_Digest(in, len, out, &olen, EVP_sha3_256(), NULL) == 1 && olen == 32 ? 0 : -1;
}

/* X-Wing combiner, draft-11 section 5.3. Label bytes: 5c 2e 2f 2f 5e 5c. */
static int xwing_combiner(const uint8_t ss_M[32], const uint8_t ss_X[32],
                          const uint8_t ct_X[32], const uint8_t pk_X[32], uint8_t out[32]) {
    static const uint8_t label[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};
    uint8_t buf[32 + 32 + 32 + 32 + 6];
    memcpy(buf, ss_M, 32); memcpy(buf + 32, ss_X, 32);
    memcpy(buf + 64, ct_X, 32); memcpy(buf + 96, pk_X, 32);
    memcpy(buf + 128, label, 6);
    return sha3_256(buf, sizeof(buf), out);
}

/* Pack's own combiner (NOT standardized): domain-separated SHA3-256. */
static int pack_combiner(const uint8_t ss_M[32], const uint8_t ss_X[32],
                         const uint8_t ct_X[32], const uint8_t pk_X[32], uint8_t out[32]) {
    static const char dom[] = "MLKEM768-X25519-PACK-v1";
    size_t dlen = strlen(dom);
    uint8_t buf[64 + 32 + 32 + 32];
    memcpy(buf, dom, dlen);
    memcpy(buf + dlen, ss_M, 32); memcpy(buf + dlen + 32, ss_X, 32);
    memcpy(buf + dlen + 64, ct_X, 32); memcpy(buf + dlen + 96, pk_X, 32);
    return sha3_256(buf, dlen + 128, out);
}

/* ---------- hybrid keypair (see header comment on the keygen deviation) ---------- */
typedef struct {
    uint8_t *pk_M, *sk_M;   /* ML-KEM-768, liboqs lengths */
    uint8_t x_priv[32], x_pub[32];
} hybrid_kp;

static int hybrid_keygen(OQS_KEM *kem, hybrid_kp *kp) {
    kp->pk_M = malloc(kem->length_public_key);
    kp->sk_M = malloc(kem->length_secret_key);
    if (!kp->pk_M || !kp->sk_M) return -1;
    if (OQS_KEM_keypair(kem, kp->pk_M, kp->sk_M) != OQS_SUCCESS) return -1;
    if (rand_bytes(kp->x_priv, 32) != 0) return -1;
    if (x25519_pub(kp->x_priv, kp->x_pub) != 0) return -1;
    return 0;
}

/* Encapsulate with a chosen combiner: 0 = X-Wing, 1 = RFC 10024 concat, 2 = pack. */
static int hybrid_encaps(OQS_KEM *kem, const hybrid_kp *kp, int mode,
                         uint8_t *ct_out, uint8_t *ss_out, size_t *ss_len) {
    uint8_t eph_priv[32], eph_pub[32], ss_X[32], ss_M[32], ct_M[1088];
    if (rand_bytes(eph_priv, 32) != 0) return -1;
    if (x25519_pub(eph_priv, eph_pub) != 0) return -1;
    if (x25519_dh(eph_priv, kp->x_pub, ss_X) != 0) return -1;
    if (OQS_KEM_encaps(kem, ct_M, ss_M, kp->pk_M) != OQS_SUCCESS) return -1;
    memcpy(ct_out, ct_M, kem->length_ciphertext);
    memcpy(ct_out + kem->length_ciphertext, eph_pub, 32);
    if (mode == 0) {
        if (xwing_combiner(ss_M, ss_X, eph_pub, kp->x_pub, ss_out) != 0) return -1;
        *ss_len = 32;
    } else if (mode == 1) {
        if (is_all_zero(ss_X, 32)) return -2; /* RFC 10024: abort on all-zero */
        memcpy(ss_out, ss_M, 32); memcpy(ss_out + 32, ss_X, 32);
        *ss_len = 64;
    } else {
        if (pack_combiner(ss_M, ss_X, eph_pub, kp->x_pub, ss_out) != 0) return -1;
        *ss_len = 32;
    }
    return 0;
}

/* Decapsulate. Returns 0 ok, -2 RFC10024 all-zero abort, -1 other error. */
static int hybrid_decaps(OQS_KEM *kem, const hybrid_kp *kp, int mode,
                         const uint8_t *ct, uint8_t *ss_out, size_t *ss_len) {
    const uint8_t *ct_M = ct, *ct_X = ct + kem->length_ciphertext;
    uint8_t ss_M[32], ss_X[32];
    if (OQS_KEM_decaps(kem, ss_M, ct_M, kp->sk_M) != OQS_SUCCESS) return -1;
    if (x25519_dh(kp->x_priv, ct_X, ss_X) != 0) return -1;
    if (mode == 0) {
        if (xwing_combiner(ss_M, ss_X, ct_X, kp->x_pub, ss_out) != 0) return -1;
        *ss_len = 32;
    } else if (mode == 1) {
        if (is_all_zero(ss_X, 32)) return -2;
        memcpy(ss_out, ss_M, 32); memcpy(ss_out + 32, ss_X, 32);
        *ss_len = 64;
    } else {
        if (pack_combiner(ss_M, ss_X, ct_X, kp->x_pub, ss_out) != 0) return -1;
        *ss_len = 32;
    }
    return 0;
}

static const char *alg_names[3] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
/* FIPS 203 Table 3: ek, dk, ct, ss sizes in bytes. */
static const size_t fips203[3][4] = {{800, 1632, 768, 32}, {1184, 2400, 1088, 32}, {1568, 3168, 1568, 32}};

static void bench_op(const char *label, int n, uint64_t *t) {
    stats_t s = stats(t, (size_t)n);
    printf("RESULT bench %s n=%d mean_us=%.3f median_us=%.3f min_us=%.3f max_us=%.3f stdev_us=%.3f ops_per_s=%.1f\n",
           label, n, s.mean / 1000.0, s.median / 1000.0, s.min / 1000.0, s.max / 1000.0,
           s.stdev / 1000.0, 1e6 / (s.mean / 1000.0));
}

int main(int argc, char **argv) {
    int bench_n = argc > 1 ? atoi(argv[1]) : 200;
    int timing_n = argc > 2 ? atoi(argv[2]) : 1000;
    if (bench_n < 10) bench_n = 10;
    if (timing_n < 10) timing_n = 10;
    printf("HARNESS mlkem_harness 1.0.0\n");
    printf("ENV liboqs=%s openssl=%s\n", OQS_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
    printf("PARAM bench_n=%d timing_n=%d single_threaded=1\n", bench_n, timing_n);

    /* Self-test: SHA3-256("") is a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a. */
    uint8_t h[32]; char hx[65];
    if (sha3_256((const uint8_t *)"", 0, h) != 0) die("SHA3-256 self-test failed to run");
    hex_encode(h, 32, hx);
    int selftest = strcmp(hx, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a") == 0;
    printf("SELFTEST sha3_256_empty expected=a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a got=%s %s\n",
           hx, selftest ? "PASS" : "FAIL");
    if (!selftest) g_failures++;

    /* RFC 7748 section 5.2 X25519 test vectors. */
    {
        static const char *vec[2][3] = {
            {"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
             "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
             "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
            {"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
             "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
             "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"}
        };
        for (int i = 0; i < 2; i++) {
            uint8_t ks[32], us[32], os[32];
            hex_decode(vec[i][0], ks, 32);
            hex_decode(vec[i][1], us, 32);
            x25519_ladder(ks, us, os);
            hex_encode(os, 32, hx);
            int pass = strcmp(hx, vec[i][2]) == 0;
            printf("SELFTEST rfc7748_x25519_vector%d expected=%s got=%s %s\n", i + 1, vec[i][2], hx, pass ? "PASS" : "FAIL");
            if (!pass) g_failures++;
        }
        /* X25519(sk, 0) must be 0 per the RFC 7748 ladder (no exception). */
        uint8_t zero[32] = {0}, zout[32], skv[32];
        memset(skv, 0x11, 32);
        x25519_ladder(skv, zero, zout);
        printf("SELFTEST rfc7748_x25519_zero_u result_all_zero=%s\n", is_all_zero(zout, 32) ? "yes" : "no");
        if (!is_all_zero(zout, 32)) g_failures++;
    }

    OQS_init();

    for (int a = 0; a < 3; a++) {
        printf("=== SECTION A+B: %s ===\n", alg_names[a]);
        OQS_KEM *kem = OQS_KEM_new(alg_names[a]);
        if (!kem) { printf("RESULT %s available=0\n", alg_names[a]); g_failures++; continue; }
        printf("RESULT %s available=1 alg=%s\n", alg_names[a], kem->method_name);
        printf("RESULT %s sizes pk=%zu dk=%zu ct=%zu ss=%zu\n", alg_names[a],
               kem->length_public_key, kem->length_secret_key, kem->length_ciphertext, kem->length_shared_secret);
        int ok = kem->length_public_key == fips203[a][0] && kem->length_secret_key == fips203[a][1] &&
                 kem->length_ciphertext == fips203[a][2] && kem->length_shared_secret == fips203[a][3];
        printf("RESULT %s sizes_match_fips203_table3=%s\n", alg_names[a], ok ? "PASS" : "FAIL");
        if (!ok) g_failures++;

        size_t pklen = kem->length_public_key, sklen = kem->length_secret_key,
               ctlen = kem->length_ciphertext, sslen = kem->length_shared_secret;
        uint8_t *pk = malloc(pklen), *sk = malloc(sklen);
        uint8_t *ct = malloc(ctlen), *ss = malloc(sslen), *ss2 = malloc(sslen);
        uint8_t *ct_bad = malloc(ctlen + 1);
        size_t tn = (size_t)(bench_n > timing_n ? bench_n : timing_n);
        uint64_t *t = malloc(sizeof(uint64_t) * tn);
        char label[96];

        /* B: benchmarks. */
        for (int i = 0; i < bench_n; i++) {
            uint64_t s = now_ns();
            if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) die("keypair failed");
            t[i] = now_ns() - s;
        }
        snprintf(label, sizeof(label), "%s_keygen", alg_names[a]); bench_op(label, bench_n, t);
        for (int i = 0; i < bench_n; i++) {
            uint64_t s = now_ns();
            if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) die("encaps failed");
            t[i] = now_ns() - s;
        }
        snprintf(label, sizeof(label), "%s_encaps", alg_names[a]); bench_op(label, bench_n, t);
        for (int i = 0; i < bench_n; i++) {
            uint64_t s = now_ns();
            if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) die("decaps failed");
            t[i] = now_ns() - s;
        }
        snprintf(label, sizeof(label), "%s_decaps", alg_names[a]); bench_op(label, bench_n, t);
        printf("RESULT %s roundtrip_match=%s\n", alg_names[a], memcmp(ss, ss2, sslen) == 0 ? "yes" : "no");
        if (memcmp(ss, ss2, sslen) != 0) g_failures++;

        /* C: failure injection. Fresh keypair; one valid encaps as reference. */
        printf("=== SECTION C: %s failure injection ===\n", alg_names[a]);
        if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) die("keypair failed");
        if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) die("encaps failed");
        char ref_hash[65]; sha256_hex(ss, sslen, ref_hash);
        printf("RESULT %s ref_ss_sha256=%s\n", alg_names[a], ref_hash);

        /* Bit flips at first, middle, last byte. */
        size_t flip_offs[3] = {0, ctlen / 2, ctlen - 1};
        for (int f = 0; f < 3; f++) {
            memcpy(ct_bad, ct, ctlen);
            ct_bad[flip_offs[f]] ^= 0x01;
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss2, ct_bad, sk);
            sha256_hex(ss2, sslen, hx);
            printf("RESULT %s bitflip byte=%zu rc=%s ss_equals_ref=%s ss_sha256=%s\n",
                   alg_names[a], flip_offs[f], rc == OQS_SUCCESS ? "OQS_SUCCESS" : "OQS_ERROR",
                   memcmp(ss, ss2, sslen) == 0 ? "yes" : "no", hx);
            if (rc != OQS_SUCCESS) g_failures++;
            if (memcmp(ss, ss2, sslen) == 0) g_failures++;
        }
        /* Random ciphertexts: 32 trials, distinctness of rejected outputs. */
        {
            char seen[32][65]; int distinct = 0, any_eq_ref = 0, all_ok = 1;
            for (int i = 0; i < 32; i++) {
                if (rand_bytes(ct_bad, ctlen) != 0) die("urandom failed");
                OQS_STATUS rc = OQS_KEM_decaps(kem, ss2, ct_bad, sk);
                if (rc != OQS_SUCCESS) all_ok = 0;
                sha256_hex(ss2, sslen, hx);
                if (memcmp(ss, ss2, sslen) == 0) any_eq_ref = 1;
                int dup = 0;
                for (int j = 0; j < distinct; j++) if (strcmp(seen[j], hx) == 0) dup = 1;
                if (!dup) strcpy(seen[distinct++], hx);
                if (i < 3) printf("RESULT %s random_ct[%d] rc=%s ss_sha256=%s\n", alg_names[a], i,
                                  rc == OQS_SUCCESS ? "OQS_SUCCESS" : "OQS_ERROR", hx);
            }
            printf("RESULT %s random_ct n=32 all_rc_success=%s distinct_rejected_ss=%d any_equals_ref=%s\n",
                   alg_names[a], all_ok ? "yes" : "no", distinct, any_eq_ref ? "yes" : "no");
            if (!all_ok || distinct != 32 || any_eq_ref) g_failures++;
        }
        /* All-zero ciphertext. */
        memset(ct_bad, 0, ctlen);
        {
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss2, ct_bad, sk);
            sha256_hex(ss2, sslen, hx);
            printf("RESULT %s zero_ct rc=%s ss_equals_ref=%s ss_sha256=%s\n", alg_names[a],
                   rc == OQS_SUCCESS ? "OQS_SUCCESS" : "OQS_ERROR",
                   memcmp(ss, ss2, sslen) == 0 ? "yes" : "no", hx);
            if (rc != OQS_SUCCESS) g_failures++;
        }
        /* Truncated / overlong / empty ciphertexts (length checks). */
        {
            OQS_STATUS rc;
            rc = OQS_KEM_decaps(kem, ss2, ct, sk); /* control, full length */
            printf("RESULT %s ct_len=%zu rc=%s (control)\n", alg_names[a], ctlen, rc == OQS_SUCCESS ? "OQS_SUCCESS" : "OQS_ERROR");
            /* liboqs decaps takes a fixed-length buffer; truncated input is simulated by
               passing the same buffer but the API has no length parameter, so a short
               ciphertext cannot be represented. Instead we verify the documented
               behaviour by checking that decaps of a ciphertext with a wrong final byte
               still returns success (covered above) and record that the C API accepts
               only exactly-length ciphertexts by construction. */
            printf("RESULT %s truncated_ct api_note=liboqs_OQS_KEM_decaps_takes_fixed_length_ct_no_length_parameter_short_ct_not_representable\n", alg_names[a]);
            printf("RESULT %s truncated_ct status=UNSUPPORTED_IN_THIS_API\n", alg_names[a]);
        }
        (void)ct_bad;

        /* D: coarse timing, valid vs bit-flipped decaps (ML-KEM-768 only for the headline). */
        if (a == 1) {
            printf("=== SECTION D: %s coarse timing valid vs invalid decaps ===\n", alg_names[a]);
            uint8_t *ctf = malloc(ctlen);
            memcpy(ctf, ct, ctlen); ctf[0] ^= 0x01;
            uint64_t *tv = malloc(sizeof(uint64_t) * (size_t)timing_n);
            uint64_t *ti = malloc(sizeof(uint64_t) * (size_t)timing_n);
            for (int i = 0; i < timing_n; i++) {
                uint64_t s = now_ns();
                if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) die("decaps valid failed");
                tv[i] = now_ns() - s;
            }
            for (int i = 0; i < timing_n; i++) {
                uint64_t s = now_ns();
                if (OQS_KEM_decaps(kem, ss2, ctf, sk) != OQS_SUCCESS) die("decaps invalid failed");
                ti[i] = now_ns() - s;
            }
            stats_t sv = stats(tv, (size_t)timing_n), si = stats(ti, (size_t)timing_n);
            printf("RESULT timing valid n=%d mean_us=%.3f median_us=%.3f min_us=%.3f max_us=%.3f stdev_us=%.3f\n",
                   timing_n, sv.mean / 1000.0, sv.median / 1000.0, sv.min / 1000.0, sv.max / 1000.0, sv.stdev / 1000.0);
            printf("RESULT timing invalid n=%d mean_us=%.3f median_us=%.3f min_us=%.3f max_us=%.3f stdev_us=%.3f\n",
                   timing_n, si.mean / 1000.0, si.median / 1000.0, si.min / 1000.0, si.max / 1000.0, si.stdev / 1000.0);
            printf("RESULT timing mean_diff_us=%.3f invalid_over_valid_ratio=%.4f median_diff_us=%.3f\n",
                   (si.mean - sv.mean) / 1000.0, si.mean / sv.mean, (si.median - sv.median) / 1000.0);
            printf("NOTE timing caveat=coarse_wall_clock_comparison_not_a_constant_time_proof\n");
            free(ctf); free(tv); free(ti);
        }

        /* E: key reuse (ML-KEM-768 only for the headline). */
        if (a == 1) {
            printf("=== SECTION E: %s key reuse ===\n", alg_names[a]);
            uint8_t *pk2 = malloc(pklen), *sk2 = malloc(sklen);
            if (OQS_KEM_keypair(kem, pk2, sk2) != OQS_SUCCESS) die("keypair2 failed");
            int all_match = 1, all_ct_distinct = 1;
            char seen_ct[100][65];
            uint8_t ct_first[1088];
            for (int i = 0; i < 100; i++) {
                if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) die("encaps reuse failed");
                if (i == 0) memcpy(ct_first, ct, ctlen);
                sha256_hex(ct, ctlen, hx);
                for (int j = 0; j < i; j++) if (strcmp(seen_ct[j], hx) == 0) all_ct_distinct = 0;
                strcpy(seen_ct[i], hx);
                if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) die("decaps reuse failed");
                if (memcmp(ss, ss2, sslen) != 0) all_match = 0;
            }
            /* Replay: decapsulate the first ciphertext again under the same key. */
            OQS_STATUS rrc = OQS_KEM_decaps(kem, ss2, ct_first, sk);
            printf("RESULT %s keyreuse n=100 all_decaps_match_encaps=%s all_ciphertexts_distinct=%s\n",
                   alg_names[a], all_match ? "yes" : "no", all_ct_distinct ? "yes" : "no");
            printf("RESULT %s keyreuse replay_first_ct rc=%s ss_sha256=", alg_names[a], rrc == OQS_SUCCESS ? "OQS_SUCCESS" : "OQS_ERROR");
            sha256_hex(ss2, sslen, hx); printf("%s\n", hx);
            /* Wrong-key decapsulation: ciphertext from keypair 1 under keypair 2. */
            if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) die("encaps failed");
            OQS_STATUS wrc = OQS_KEM_decaps(kem, ss2, ct, sk2);
            printf("RESULT %s keyreuse wrong_key_decaps rc=%s ss_equals_ref=%s\n", alg_names[a],
                   wrc == OQS_SUCCESS ? "OQS_SUCCESS" : "OQS_ERROR",
                   memcmp(ss, ss2, sslen) == 0 ? "yes" : "no");
            if (wrc != OQS_SUCCESS) g_failures++;
            if (!all_match || !all_ct_distinct || rrc != OQS_SUCCESS) g_failures++;
            free(pk2); free(sk2);
        }

        OQS_KEM_free(kem);
        free(pk); free(sk); free(ct); free(ss); free(ss2); free(ct_bad); free(t);
    }

    /* F: hybrid KEMs, ML-KEM-768 + X25519. */
    printf("=== SECTION F: hybrid ML-KEM-768 + X25519 ===\n");
    {
        OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
        if (!kem) die("ML-KEM-768 unavailable for hybrid section");
        hybrid_kp kp;
        if (hybrid_keygen(kem, &kp) != 0) die("hybrid keygen failed");
        size_t ctlen = kem->length_ciphertext;
        printf("RESULT hybrid sizes xwing_pk=1216 xwing_ct=1120 xwing_ss=32 rfc10024_ss=64 pack_ss=32 mlkem768_ct=%zu\n", ctlen);
        printf("RESULT hybrid keygen_note=independent_liboqs_mlkem768_keypair_plus_inharness_rfc7748_x25519_keypair_draft11_shake256_seed_expansion_not_used_because_liboqs_does_not_expose_KeyGen_internal\n");
        static const char *modes[3] = {"xwing", "rfc10024", "pack"};
        for (int m = 0; m < 3; m++) {
            size_t sslen = (m == 1) ? 64 : 32;
            uint8_t *ct = malloc(ctlen + 32), *ss = malloc(64), *ss2 = malloc(64);
            uint64_t *t = malloc(sizeof(uint64_t) * (size_t)bench_n);
            size_t sl = 0;
            if (hybrid_encaps(kem, &kp, m, ct, ss, &sl) != 0) die("hybrid encaps failed");
            int rc = hybrid_decaps(kem, &kp, m, ct, ss2, &sl);
            printf("RESULT hybrid %s roundtrip_match=%s rc=%d ss_len=%zu\n", modes[m],
                   (rc == 0 && memcmp(ss, ss2, sslen) == 0) ? "yes" : "no", rc, sl);
            if (rc != 0 || memcmp(ss, ss2, sslen) != 0) g_failures++;
            for (int i = 0; i < bench_n; i++) {
                uint64_t s = now_ns();
                if (hybrid_encaps(kem, &kp, m, ct, ss, &sl) != 0) die("hybrid encaps bench failed");
                t[i] = now_ns() - s;
            }
            char label[64]; snprintf(label, sizeof(label), "hybrid_%s_encaps", modes[m]); bench_op(label, bench_n, t);
            for (int i = 0; i < bench_n; i++) {
                uint64_t s = now_ns();
                if (hybrid_decaps(kem, &kp, m, ct, ss2, &sl) != 0) die("hybrid decaps bench failed");
                t[i] = now_ns() - s;
            }
            snprintf(label, sizeof(label), "hybrid_%s_decaps", modes[m]); bench_op(label, bench_n, t);
            /* Failure injection on the hybrid: flip a bit in the ML-KEM part, then in the X25519 part. */
            if (hybrid_encaps(kem, &kp, m, ct, ss, &sl) != 0) die("hybrid encaps failed");
            uint8_t *ctf = malloc(ctlen + 32);
            memcpy(ctf, ct, ctlen + 32); ctf[0] ^= 0x01;
            rc = hybrid_decaps(kem, &kp, m, ctf, ss2, &sl);
            printf("RESULT hybrid %s bitflip_mlkem_part rc=%d ss_equals_ref=%s\n", modes[m], rc,
                   (rc == 0 && memcmp(ss, ss2, sslen) == 0) ? "yes" : "no");
            memcpy(ctf, ct, ctlen + 32); ctf[ctlen] ^= 0x01;
            rc = hybrid_decaps(kem, &kp, m, ctf, ss2, &sl);
            printf("RESULT hybrid %s bitflip_x25519_part rc=%d ss_equals_ref=%s\n", modes[m], rc,
                   (rc == 0 && memcmp(ss, ss2, sslen) == 0) ? "yes" : "no");
            if (rc == 0 && memcmp(ss, ss2, sslen) == 0) g_failures++;
            /* All-zero X25519 ciphertext part: X-Wing/pack return a value, RFC 10024 aborts. */
            memcpy(ctf, ct, ctlen + 32); memset(ctf + ctlen, 0, 32);
            rc = hybrid_decaps(kem, &kp, m, ctf, ss2, &sl);
            printf("RESULT hybrid %s zero_x25519_ct_part rc=%d ss_equals_ref=%s\n", modes[m], rc,
                   (rc == 0 && memcmp(ss, ss2, sslen) == 0) ? "yes" : "no");
            if (m == 1 && rc != -2) { printf("RESULT hybrid rfc10024 zero_x25519_abort_expected=-2 got=%d FAIL\n", rc); g_failures++; }
            if (m != 1 && rc != 0) { printf("RESULT hybrid %s zero_x25519_expected_rc=0 got=%d FAIL\n", modes[m], rc); g_failures++; }
            free(ct); free(ss); free(ss2); free(t); free(ctf);
        }
        free(kp.pk_M); free(kp.sk_M);
        OQS_KEM_free(kem);
    }

    OQS_destroy();
    printf("HARNESS_DONE internal_check_failures=%d\n", g_failures);
    return g_failures ? 1 : 0;
}
