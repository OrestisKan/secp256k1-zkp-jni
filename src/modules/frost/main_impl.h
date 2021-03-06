/**********************************************************************
 * Copyright (c) 2021 Jesse Posner, Andrew Poelstra                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_MAIN_H
#define SECP256K1_MODULE_FROST_MAIN_H

#include "include/secp256k1.h"
#include "include/secp256k1_frost.h"
#include "../musig/keyagg.h"
#include "../musig/session.h"
#include "hash.h"

/* Generate polynomial coefficients, coefficient commitments, and shares, from
 * a seed and a secret key. */
static int secp256k1_frost_share_gen_internal(const secp256k1_context *ctx, secp256k1_pubkey *pubcoeff, secp256k1_frost_share *shares, size_t threshold, size_t n_participants, const unsigned char *seckey32, const unsigned char *pk_hash) {
    secp256k1_sha256 sha;
    size_t i;
    int overflow;
    secp256k1_scalar const_term;
    secp256k1_gej rj;
    secp256k1_ge rp;
    unsigned char rngseed[32];

    ARG_CHECK(seckey32 != NULL);

    /* Compute seed which commits to all inputs */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, pk_hash, 32);
    secp256k1_sha256_write(&sha, seckey32, 32);
    for (i = 0; i < 8; i++) {
        rngseed[i + 0] = threshold / (1ull << (i * 8));
        rngseed[i + 8] = n_participants / (1ull << (i * 8));
    }
    secp256k1_sha256_write(&sha, rngseed, 16);
    secp256k1_sha256_finalize(&sha, rngseed);

    secp256k1_scalar_set_b32(&const_term, seckey32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &const_term);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&pubcoeff[0], &rp);

    /* Derive coefficients from the seed */
    for (i = 0; i < threshold - 1; i++) {
        secp256k1_scalar rand[2];

        if (i % 2 == 0) {
            secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
        }
        /* Compute commitment to each coefficient */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubcoeff[threshold - i - 1], &rp);
    }

    for (i = 0; i < n_participants; i++) {
        size_t j;
        secp256k1_scalar share_i;
        secp256k1_scalar scalar_i;
        secp256k1_scalar rand[2];

        secp256k1_scalar_clear(&share_i);
        secp256k1_scalar_set_int(&scalar_i, i + 1);
        for (j = 0; j < threshold - 1; j++) {
            if (j % 2 == 0) {
                secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, j);
            }

            /* Horner's method to evaluate polynomial to derive shares */
            secp256k1_scalar_add(&share_i, &share_i, &rand[j % 2]);
            secp256k1_scalar_mul(&share_i, &share_i, &scalar_i);
        }
        secp256k1_scalar_add(&share_i, &share_i, &const_term);
        secp256k1_scalar_get_b32(shares[i].data, &share_i);
    }

    return 1;
}

int secp256k1_frost_share_gen(const secp256k1_context *ctx, secp256k1_pubkey *pubcoeff, secp256k1_frost_share *shares, size_t threshold, size_t n_participants, const secp256k1_keypair *keypair, const secp256k1_musig_keyagg_cache *keyagg_cache) {
    secp256k1_scalar sk;
    secp256k1_ge pk;
    secp256k1_scalar mu;
    secp256k1_keyagg_cache_internal cache_i;
    unsigned char buf[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(pubcoeff != NULL);
    ARG_CHECK(shares != NULL);
    ARG_CHECK(n_participants > 0);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(keyagg_cache != NULL);

    if (threshold == 0 || threshold > n_participants) {
        return 0;
    }

    if (!secp256k1_keypair_load(ctx, &sk, &pk, keypair)) {
        return 0;
    }
    if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    /* TODO: Can we move to this signing time? */
    secp256k1_fe_normalize_var(&pk.y);
    if ((secp256k1_fe_is_odd(&pk.y)
         != secp256k1_fe_is_odd(&cache_i.pk.y))
         != cache_i.internal_key_parity) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    /* Multiply KeyAgg coefficient */
    secp256k1_fe_normalize_var(&pk.x);
    secp256k1_musig_keyaggcoef(&mu, &cache_i, &pk.x);
    secp256k1_scalar_mul(&sk, &sk, &mu);
    secp256k1_scalar_get_b32(buf, &sk);

    if (!secp256k1_frost_share_gen_internal(ctx, pubcoeff, shares, threshold, n_participants, buf, cache_i.pk_hash)) {
        return 0;
    }

    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("VSS list")||SHA256("VSS list"). */
static void secp256k1_frost_vsslist_sha256(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);

    sha->s[0] = 0x3c261fccul;
    sha->s[1] = 0xeeec1555ul;
    sha->s[2] = 0x6bb6cfc8ul;
    sha->s[3] = 0x678ade57ul;
    sha->s[4] = 0xfb4b11f9ul;
    sha->s[5] = 0x9627b131ul;
    sha->s[6] = 0xbf978156ul;
    sha->s[7] = 0xfc1263cdul;
    sha->bytes = 64;
}

/* Computes vss_hash = tagged_hash(pk[0], ..., pk[np-1]) */
static int secp256k1_frost_compute_vss_hash(const secp256k1_context *ctx, unsigned char *vss_hash, const secp256k1_pubkey * const* pk, size_t np, size_t t) {
    secp256k1_sha256 sha;
    size_t i, j;
    size_t size = 33;

    secp256k1_frost_vsslist_sha256(&sha);
    for (i = 0; i < np; i++) {
        for (j = 0; j < t; j++) {
            unsigned char ser[33];
            if (!secp256k1_ec_pubkey_serialize(ctx, ser, &size, &pk[i][j], SECP256K1_EC_COMPRESSED)) {
                return 0;
            }
            secp256k1_sha256_write(&sha, ser, 33);
        }
    }
    secp256k1_sha256_finalize(&sha, vss_hash);

    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    secp256k1_scalar idx;
    secp256k1_scalar idxn;
    const secp256k1_pubkey * const* pubcoeff;
} secp256k1_musig_verify_share_ecmult_data;

static int secp256k1_frost_verify_share_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_verify_share_ecmult_data *ctx = (secp256k1_musig_verify_share_ecmult_data *) data;
    int ret;

    ret = secp256k1_pubkey_load(ctx->ctx, pt, *(ctx->pubcoeff)+idx);
    VERIFY_CHECK(ret);
    secp256k1_scalar_mul(sc, &secp256k1_scalar_one, &ctx->idxn);
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

int secp256k1_frost_share_agg(const secp256k1_context* ctx, secp256k1_frost_share *agg_share, unsigned char *vss_hash, const secp256k1_frost_share * const* shares, const secp256k1_pubkey * const* pubcoeffs, size_t n_shares, size_t threshold, size_t my_index) {
    secp256k1_scalar acc;
    size_t i;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_share != NULL);
    ARG_CHECK(vss_hash != NULL);
    ARG_CHECK(shares != NULL);
    ARG_CHECK(pubcoeffs != NULL);
    ARG_CHECK(n_shares > 0);
    ARG_CHECK(my_index > 0);

    if (threshold == 0 || threshold > n_shares) {
        return 0;
    }

    secp256k1_scalar_clear(&acc);
    for (i = 0; i < n_shares; i++) {
        secp256k1_scalar share_i;
        secp256k1_musig_verify_share_ecmult_data ecmult_data;
        secp256k1_gej sharej;
        secp256k1_gej expectedj;

        secp256k1_scalar_set_b32(&share_i, shares[i]->data, &overflow);
        if (overflow) {
            return 0;
        }

        ecmult_data.ctx = ctx;
        ecmult_data.pubcoeff = &pubcoeffs[i];
        /* Evaluate the public polynomial at the index */
        secp256k1_scalar_set_int(&ecmult_data.idx, my_index);
        secp256k1_scalar_set_int(&ecmult_data.idxn, 1);
        /* TODO: add scratch */
        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &sharej, NULL, secp256k1_frost_verify_share_ecmult_callback, (void *) &ecmult_data, threshold)) {
            return 0;
        }
        /* Verify share using VSS */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &expectedj, &share_i);
        secp256k1_gej_neg(&expectedj, &expectedj);
        secp256k1_gej_add_var(&expectedj, &expectedj, &sharej, NULL);
        if (!secp256k1_gej_is_infinity(&expectedj)) {
            return 0;
        }

        secp256k1_scalar_add(&acc, &acc, &share_i);
    }
    secp256k1_scalar_get_b32((unsigned char *) agg_share->data, &acc);

    if (!secp256k1_frost_compute_vss_hash(ctx, vss_hash, pubcoeffs, n_shares, threshold)) {
        return 0;
    }

    return 1;
}

static void secp256k1_frost_lagrange_coefficient(secp256k1_scalar *r, size_t *participant_indexes, size_t n_participants, size_t my_index) {
    size_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar idx;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    secp256k1_scalar_set_int(&idx, my_index);
    for (i = 0; i < n_participants; i++) {
        secp256k1_scalar mul;
        if (participant_indexes[i] == my_index) {
            continue;
        }
        secp256k1_scalar_set_int(&mul, participant_indexes[i]);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);

        secp256k1_scalar_add(&mul, &mul, &idx);
        secp256k1_scalar_mul(&den, &den, &mul);
    }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);
}

int secp256k1_frost_partial_sign(const secp256k1_context* ctx, secp256k1_musig_partial_sig *partial_sig, secp256k1_musig_secnonce *secnonce, const secp256k1_frost_share *agg_share, const secp256k1_musig_session *session, size_t n_signers, size_t *indexes, size_t my_index) {
    secp256k1_scalar sk, l;
    secp256k1_scalar k[2];
    secp256k1_scalar s;
    secp256k1_musig_session_internal session_i;
    int ret;
    int overflow;

    VERIFY_CHECK(ctx != NULL);

    ARG_CHECK(secnonce != NULL);
    /* Fails if the magic doesn't match */
    ret = secp256k1_musig_secnonce_load(ctx, k, secnonce);
    /* Set nonce to zero to avoid nonce reuse. This will cause subsequent calls
     * of this function to fail */
    memset(secnonce, 0, sizeof(*secnonce));
    if (!ret) {
        secp256k1_musig_partial_sign_clear(&sk, k);
        return 0;
    }

    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(agg_share != NULL);
    ARG_CHECK(session != NULL);

    secp256k1_scalar_set_b32(&sk, agg_share->data, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_musig_session_load(ctx, &session_i, session)) {
        secp256k1_musig_partial_sign_clear(&sk, k);
        return 0;
    }
    if (session_i.fin_nonce_parity) {
        secp256k1_scalar_negate(&k[0], &k[0]);
        secp256k1_scalar_negate(&k[1], &k[1]);
    }

    /* Sign */
    secp256k1_frost_lagrange_coefficient(&l, indexes, n_signers, my_index);
    secp256k1_scalar_mul(&sk, &sk, &l);
    secp256k1_scalar_mul(&s, &session_i.challenge, &sk);
    secp256k1_scalar_mul(&k[1], &session_i.noncecoef, &k[1]);
    secp256k1_scalar_add(&k[0], &k[0], &k[1]);
    secp256k1_scalar_add(&s, &s, &k[0]);
    secp256k1_musig_partial_sig_save(partial_sig, &s);
    secp256k1_musig_partial_sign_clear(&sk, k);
    return 1;
}

#endif
