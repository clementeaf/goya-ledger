/*
 * ACVP deterministic primitives for CMVP certification testing.
 *
 * goya_mldsa65_sign_internal_derand  — FIPS 204 Sign_internal with injected rnd
 * goya_mldsa65_sign_external_derand  — FIPS 204 ML-DSA.Sign with context + injected rnd
 * goya_mldsa65_verify_internal       — FIPS 204 Verify_internal (no domain separator)
 *
 * ML-KEM-768 derand functions already exist in PQClean as
 * crypto_kem_keypair_derand and crypto_kem_enc_derand — we link to them
 * directly via extern "C" in Rust (no C wrapper needed).
 */

#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include <string.h>

/*
 * Deterministic ML-DSA-65 internal signing (FIPS 204 §5.1 Sign_internal).
 * mu = H(tr || msg) — no domain separator, no context.
 * rnd is injected instead of generated via randombytes().
 */
int goya_mldsa65_sign_internal_derand(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t provided_rnd[RNDBYTES]
) {
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + RNDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute mu = CRH(tr || msg) — internal mode, no domain separator */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Use provided rnd instead of randombytes() */
    memcpy(rnd, provided_rnd, RNDBYTES);
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(&w1, &w0, &w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_MLDSA65_CLEAN_poly_challenge(&cp, sig);
    PQCLEAN_MLDSA65_CLEAN_poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_add(&z, &z, &y);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(&z);
    if (PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&w0, &w0, &h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w0);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    /* Compute hints for w1 */
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    /* Write signature */
    PQCLEAN_MLDSA65_CLEAN_pack_sig(sig, sig, &z, &h);
    *siglen = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
    return 0;
}

/*
 * External mode signing with context (FIPS 204 §5.2 ML-DSA.Sign).
 * mu = H(tr || 0x00 || ctxlen || ctx || msg) — pure mode with context.
 */
int goya_mldsa65_sign_external_derand(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *ctx,
    size_t ctxlen,
    const uint8_t *sk,
    const uint8_t provided_rnd[RNDBYTES]
) {
    if (ctxlen > 255) {
        return -1;
    }

    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + RNDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* mu = H(tr || 0x00 || ctxlen || ctx || msg) */
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    memcpy(rnd, provided_rnd, RNDBYTES);
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&t0);

rej2:
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);
    z = y;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(&w1, &w0, &w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_MLDSA65_CLEAN_poly_challenge(&cp, sig);
    PQCLEAN_MLDSA65_CLEAN_poly_ntt(&cp);

    PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_add(&z, &z, &y);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(&z);
    if (PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej2;
    }
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&w0, &w0, &h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w0);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej2;
    }
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&h, GAMMA2)) {
        goto rej2;
    }
    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej2;
    }

    PQCLEAN_MLDSA65_CLEAN_pack_sig(sig, sig, &z, &h);
    *siglen = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
    return 0;
}
