#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bitcoin_NativeSecp256k1.h"
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_recovery.h"
#include "include/secp256k1_schnorrsig.h"
#include "include/secp256k1_musig.h"
#include "include/secp256k1_frost.h"
#include <stdio.h>
#include "jni_struct_convertor.c"

#define RANDOM "/dev/urandom"

/* Create shares and coefficient commitments */
int send_shares(const secp256k1_context* ctx,
                secp256k1_frost_share *shares,
                const secp256k1_xonly_pubkey **pubkeys,
                struct signer_secrets *signer_secret, struct signer *signer, int n_signers, int threshold) {
    /* The same for all signers */
    secp256k1_musig_keyagg_cache cache;

    FILE *frand;
    unsigned char seckey[32];
    unsigned char session_id[32];
    /* Create random session ID. It is absolutely necessary that the session ID
     * is unique for every call of secp256k1_musig_nonce_gen. Otherwise
     * it's trivial for an attacker to extract the secret key! */
    frand = fopen(RANDOM, "r");
    if(frand == NULL) {
        return 0;
    }
    if (!fread(session_id, 32, 1, frand)) {
        fclose(frand);
        return 0;
    }
    fclose(frand);
    if (!secp256k1_keypair_sec(ctx, seckey, &signer_secret->keypair)) {
        return 0;
    }

    /* Initialize session and create secret nonce for signing and public
     * nonce to send to the other signers. */
    if (!secp256k1_musig_nonce_gen(ctx, &signer_secret->secnonce, &signer->pubnonce, session_id, seckey, NULL, NULL, NULL)) {
        return 0;
    }

    if (!secp256k1_musig_pubkey_agg(ctx, NULL, NULL, &cache, pubkeys, n_signers)) {
        return 0;
    }
    /* Generate a polynomial share for each participant */
    if (!secp256k1_frost_share_gen(ctx, signer->pubcoeff, shares, threshold, n_signers, &signer_secret->keypair, &cache)) {
        return 0;
    }
    return 1;
}

int sign_vss_send(const secp256k1_context* ctx,
                  const secp256k1_xonly_pubkey **pubkeys,
                  const secp256k1_musig_pubnonce **pubnonces,
                  struct signer_secrets *signer_secret, struct signer *signer,
                  secp256k1_musig_keyagg_cache *cache, secp256k1_musig_session *session, int n_signers) {
    secp256k1_musig_aggnonce agg_pubnonce;

    /* Create aggregate pubkey, aggregate nonce and initialize signer data */
    if (!secp256k1_musig_pubkey_agg(ctx, NULL, NULL, cache, pubkeys, n_signers)) {
        return 0;
    }

    if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, n_signers)) {
        return 0;
    }

    if (!secp256k1_musig_nonce_process(ctx, session, &agg_pubnonce, signer->vss_hash, cache, NULL)) {
        return 0;
    }

    if (!secp256k1_musig_partial_sign(ctx, &signer->partial_sig, &signer_secret->secnonce, &signer_secret->keypair, cache, session)) {
        return 0;
    }

    return 1;
}

int sign_vss_receive(const secp256k1_context* ctx, struct signer *signer, secp256k1_musig_session *session, secp256k1_musig_keyagg_cache *cache) {

    if (!secp256k1_musig_partial_sig_verify(ctx, &signer->partial_sig, &signer->pubnonce, &signer->pubkey, cache, session)) {
        return 0;
    }
    return 1;
}

int partial_signs_aggregate(const secp256k1_context* ctx,
                            const secp256k1_musig_partial_sig **partial_sigs,
                            unsigned char *sig64, secp256k1_musig_session *session, int n_signers) {

    return secp256k1_musig_partial_sig_agg(ctx, sig64, session, partial_sigs, n_signers);
}

/**
 * Method to create a key pair for each participant
 * @param ctx
 * @param pubkey pointer to the publickey
 * @param keypair pointer to the keypair
 * @return success/failure
 */
int create_key_pair_java(const secp256k1_context* ctx, secp256k1_xonly_pubkey* pubkey, secp256k1_keypair* keypair)
{
    unsigned char seckey[32];
    FILE *frand = fopen(RANDOM, "r");
    if (frand == NULL) {
        return 0;
    }
    do {
        if(!fread(seckey, sizeof(seckey), 1, frand)) {
            fclose(frand);
            return 0;
        }
        /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
    fclose(frand);
    if (!secp256k1_keypair_create(ctx, keypair, seckey)) {
        return 0;
    }
    if (!secp256k1_keypair_xonly_pub(ctx, pubkey, NULL, keypair)) {
        return 0;
    }
    return 1;
}

int sign_message_step0(const secp256k1_context* ctx, struct signer_secrets *signer_secret, struct signer *signer, const unsigned char* msg32) {
    /* The same for all signers */
    FILE *frand;
    unsigned char seckey[32];
    unsigned char session_id[32];
    /* Create random session ID. It is absolutely necessary that the session ID
     * is unique for every call of secp256k1_musig_nonce_gen. Otherwise
     * it's trivial for an attacker to extract the secret key! */
    frand = fopen(RANDOM, "r");
    if (frand == NULL) {
        printf("frand\n");
        return 0;
    }
    if (!fread(session_id, 32, 1, frand)) {
        fclose(frand);
        printf("frand\n");
        return 0;
    }
    fclose(frand);
    if (!secp256k1_keypair_sec(ctx, seckey, &signer_secret->keypair)) {
        printf("----secret\n");
        return 0;
    }
    /* Initialize session and create secret nonce for signing and public
     * nonce to send to the other signers. */
    if (!secp256k1_musig_nonce_gen(ctx, &signer_secret->secnonce, &signer->pubnonce, session_id, seckey, msg32,
                                   NULL, NULL)) {
        return 0;
    }
    return 1;
}


int sign_message_step1(const secp256k1_context* ctx, struct signer_secrets *signer_secret,
                       struct signer *signer, const unsigned char* msg32,
                        secp256k1_xonly_pubkey **pubkeys,
                        secp256k1_musig_pubnonce **pubnonces,
                       size_t *participants, int i,
                       secp256k1_musig_session *session, secp256k1_musig_keyagg_cache *cache, int n_signers, int threshold) {
    /* The same for all signers */
    secp256k1_musig_aggnonce agg_pubnonce;

    /* Create aggregate pubkey, aggregate nonce and initialize signer data */
    if (!secp256k1_musig_pubkey_agg(ctx, NULL, NULL, cache, (const secp256k1_xonly_pubkey *const *) pubkeys, n_signers)) {
        return 0;
    }
    if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, (const secp256k1_musig_pubnonce *const *) pubnonces, threshold)) {
        return 0;
    }
    if (!secp256k1_musig_nonce_process(ctx, session, &agg_pubnonce, msg32, cache, NULL)) {
        return 0;
    }
    /* partial_sign will clear the secnonce by setting it to 0. That's because
     * you must _never_ reuse the secnonce (or use the same session_id to
     * create a secnonce). If you do, you effectively reuse the nonce and
     * leak the secret key. */
    if (!secp256k1_frost_partial_sign(ctx, &signer->partial_sig, &signer_secret->secnonce, &signer_secret->agg_share, session, threshold, participants, i+1)) {
        return 0;
    }
    return 1;
}

SECP256K1_API jlong JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1ctx_1clone
        (JNIEnv* env, jclass classObject, jlong ctx_l)
{
    const secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    jlong ctx_clone_l = (uintptr_t) secp256k1_context_clone(ctx);

    (void)classObject;(void)env;

    return ctx_clone_l;

}

SECP256K1_API jint JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1context_1randomize
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    const unsigned char* seed = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

    (void)classObject;

    return secp256k1_context_randomize(ctx, seed);

}

SECP256K1_API void JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1destroy_1context
    (JNIEnv* env, jclass classObject, jlong ctx_l)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    secp256k1_context_destroy(ctx);

    (void)classObject;(void)env;
}

SECP256K1_API jint JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint siglen, jint publen)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
    const unsigned char* sigdata = {  (unsigned char*) (data + 32) };
    const unsigned char* pubdata = { (unsigned char*) (data + siglen + 32) };

    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey;

    int ret = secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigdata, siglen);

    if( ret ) {
        ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pubdata, publen);

        if( ret ) {
            ret = secp256k1_ecdsa_verify(ctx, &sig, data, &pubkey);
        }
    }

    (void)classObject;

    return ret;
}

SECP256K1_API jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
    unsigned char* secKey = (unsigned char*) (data + 32);

    jobjectArray retArray;
    jbyteArray sigArray, intsByteArray;
    unsigned char intsarray[2];

    secp256k1_ecdsa_signature sig;

    int ret = secp256k1_ecdsa_sign(ctx, &sig, data, secKey, NULL, NULL);

    unsigned char outputSer[72];
    size_t outputLen = 72;

    if( ret ) {
        int ret2 = secp256k1_ecdsa_signature_serialize_der(ctx,outputSer, &outputLen, &sig ); (void)ret2;
    }

    intsarray[0] = outputLen;
    intsarray[1] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    sigArray = (*env)->NewByteArray(env, outputLen);
    (*env)->SetByteArrayRegion(env, sigArray, 0, outputLen, (jbyte*)outputSer);
    (*env)->SetObjectArrayElement(env, retArray, 0, sigArray);

    intsByteArray = (*env)->NewByteArray(env, 2);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;

    return retArray;
}

SECP256K1_API jint JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1ec_1seckey_1verify
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

    (void)classObject;

    return secp256k1_ec_seckey_verify(ctx, secKey);
}

SECP256K1_API jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1create
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    const unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

    secp256k1_pubkey pubkey;

    jobjectArray retArray;
    jbyteArray pubkeyArray, intsByteArray;
    unsigned char intsarray[2];

    int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, secKey);

    unsigned char outputSer[65];
    size_t outputLen = 65;

    if( ret ) {
        int ret2 = secp256k1_ec_pubkey_serialize(ctx,outputSer, &outputLen, &pubkey,SECP256K1_EC_UNCOMPRESSED );(void)ret2;
    }

    intsarray[0] = outputLen;
    intsarray[1] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    pubkeyArray = (*env)->NewByteArray(env, outputLen);
    (*env)->SetByteArrayRegion(env, pubkeyArray, 0, outputLen, (jbyte*)outputSer);
    (*env)->SetObjectArrayElement(env, retArray, 0, pubkeyArray);

    intsByteArray = (*env)->NewByteArray(env, 2);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;

    return retArray;

}

SECP256K1_API jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1add
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    unsigned char* privkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
    const unsigned char* tweak = (unsigned char*) (privkey + 32);

    jobjectArray retArray;
    jbyteArray privArray, intsByteArray;
    unsigned char intsarray[2];

    int privkeylen = 32;

    int ret = secp256k1_ec_privkey_tweak_add(ctx, privkey, tweak);

    intsarray[0] = privkeylen;
    intsarray[1] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    privArray = (*env)->NewByteArray(env, privkeylen);
    (*env)->SetByteArrayRegion(env, privArray, 0, privkeylen, (jbyte*)privkey);
    (*env)->SetObjectArrayElement(env, retArray, 0, privArray);

    intsByteArray = (*env)->NewByteArray(env, 2);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;

    return retArray;
}

SECP256K1_API jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1mul
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    unsigned char* privkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
    const unsigned char* tweak = (unsigned char*) (privkey + 32);

    jobjectArray retArray;
    jbyteArray privArray, intsByteArray;
    unsigned char intsarray[2];

    int privkeylen = 32;

    int ret = secp256k1_ec_privkey_tweak_mul(ctx, privkey, tweak);

    intsarray[0] = privkeylen;
    intsarray[1] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    privArray = (*env)->NewByteArray(env, privkeylen);
    (*env)->SetByteArrayRegion(env, privArray, 0, privkeylen, (jbyte*)privkey);
    (*env)->SetObjectArrayElement(env, retArray, 0, privArray);

    intsByteArray = (*env)->NewByteArray(env, 2);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;

    return retArray;
}

SECP256K1_API jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1add
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
/*  secp256k1_pubkey* pubkey = (secp256k1_pubkey*) (*env)->GetDirectBufferAddress(env, byteBufferObject);*/
    unsigned char* pkey = (*env)->GetDirectBufferAddress(env, byteBufferObject);
    const unsigned char* tweak = (unsigned char*) (pkey + publen);

    jobjectArray retArray;
    jbyteArray pubArray, intsByteArray;
    unsigned char intsarray[2];
    unsigned char outputSer[65];
    size_t outputLen = 65;

    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pkey, publen);

    if( ret ) {
        ret = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak);
    }

    if( ret ) {
        int ret2 = secp256k1_ec_pubkey_serialize(ctx,outputSer, &outputLen, &pubkey,SECP256K1_EC_UNCOMPRESSED );(void)ret2;
    }

    intsarray[0] = outputLen;
    intsarray[1] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    pubArray = (*env)->NewByteArray(env, outputLen);
    (*env)->SetByteArrayRegion(env, pubArray, 0, outputLen, (jbyte*)outputSer);
    (*env)->SetObjectArrayElement(env, retArray, 0, pubArray);

    intsByteArray = (*env)->NewByteArray(env, 2);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;

    return retArray;
}

SECP256K1_API jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1mul
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    unsigned char* pkey = (*env)->GetDirectBufferAddress(env, byteBufferObject);
    const unsigned char* tweak = (unsigned char*) (pkey + publen);

    jobjectArray retArray;
    jbyteArray pubArray, intsByteArray;
    unsigned char intsarray[2];
    unsigned char outputSer[65];
    size_t outputLen = 65;

    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pkey, publen);

    if ( ret ) {
        ret = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, tweak);
    }

    if( ret ) {
        int ret2 = secp256k1_ec_pubkey_serialize(ctx,outputSer, &outputLen, &pubkey,SECP256K1_EC_UNCOMPRESSED );(void)ret2;
    }

    intsarray[0] = outputLen;
    intsarray[1] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    pubArray = (*env)->NewByteArray(env, outputLen);
    (*env)->SetByteArrayRegion(env, pubArray, 0, outputLen, (jbyte*)outputSer);
    (*env)->SetObjectArrayElement(env, retArray, 0, pubArray);

    intsByteArray = (*env)->NewByteArray(env, 2);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;

    return retArray;
}

SECP256K1_API jlong JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1pubkey_1combine
        (JNIEnv * env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint numkeys)
{
    (void)classObject;(void)env;(void)byteBufferObject;(void)ctx_l;(void)numkeys;

    return 0;
}

SECP256K1_API jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_secp256k1_1ecdh
        (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    const unsigned char* secdata = (*env)->GetDirectBufferAddress(env, byteBufferObject);
    const unsigned char* pubdata = (const unsigned char*) (secdata + 32);

    jobjectArray retArray;
    jbyteArray outArray, intsByteArray;
    unsigned char intsarray[1];
    secp256k1_pubkey pubkey;
    unsigned char nonce_res[32];
    size_t outputLen = 32;

    int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pubdata, publen);

    if (ret) {
        ret = secp256k1_ecdh(
                ctx,
                nonce_res,
                &pubkey,
                secdata,
                NULL,
                NULL
        );
    }

    intsarray[0] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    outArray = (*env)->NewByteArray(env, outputLen);
    (*env)->SetByteArrayRegion(env, outArray, 0, 32, (jbyte*)nonce_res);
    (*env)->SetObjectArrayElement(env, retArray, 0, outArray);

    intsByteArray = (*env)->NewByteArray(env, 1);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 1, (jbyte*)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;

    return retArray;
}

/*TODO release (eventually)!!*/


JNIEXPORT void JNICALL Java_bitcoin_NativeSecp256k1_generate_1key(JNIEnv * env, jclass classObject,
        jobject secretj, jobject signerj, jlong ctx_l) {
    struct signer signer;
    struct signer_secrets secret;
    secp256k1_context *ctx;

    ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    signer = *(struct signer *) malloc(sizeof(struct signer));
    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));

    secret_java_to_c(env, secretj, &secret);
    signer_java_to_c(env, signerj, &signer);

    if(!create_keypair(ctx, &secret, &signer)) {
        printf("failure\n");/*TODO throw java exception*/
    }

    secret_c_to_java(env, secretj, &secret);
    signer_c_to_java(env, signerj, &signer);

    (void)classObject;
}

JNIEXPORT jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_send_1shares(JNIEnv * env, jclass classObject, jobjectArray public_keys, jobject secretj, jobject signerj, jlong ctx_l) {
    struct signer signer;
    struct signer_secrets secret;
    jbyteArray * bytes;
    jbyteArray outArray;
    jobjectArray retArray;
    jbyte *b;
    int i, n_signers, threshold = 0;
    size_t j;
    secp256k1_xonly_pubkey **pub_key_ptr;
    secp256k1_context *ctx;
    secp256k1_frost_share *shares;

    n_signers = get_n_signers(env, public_keys);
    threshold = get_threshold(env, signerj);
    pub_key_ptr = (secp256k1_xonly_pubkey **) malloc(n_signers * sizeof(secp256k1_xonly_pubkey *));

    ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    for (i = 0; i < n_signers; i++) {
        pub_key_ptr[i] = (secp256k1_xonly_pubkey *) malloc(sizeof(secp256k1_xonly_pubkey));
        bytes = (jbyteArray * )(*env)->GetObjectArrayElement(env, public_keys, i);
        b = (jbyte * )(*env)->GetByteArrayElements(env, (jbyteArray) bytes, NULL);
        for (j = 0; j < 64; j++) {
            pub_key_ptr[i]->data[j] = (unsigned char) b[j];
        }
    }

    signer = *(struct signer *) malloc(sizeof(struct signer));
    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));

    secret_java_to_c(env, secretj, &secret);
    signer_java_to_c(env, signerj, &signer);

    shares = (secp256k1_frost_share *) malloc (n_signers * sizeof(secp256k1_frost_share));

    if(!send_shares(ctx, shares, (const secp256k1_xonly_pubkey **) pub_key_ptr, &secret, &signer, n_signers, threshold)) {
        printf("FAILURE\n"); /*TODO throw java exception*/
    }

    secret_c_to_java(env, secretj, &secret);
    signer_c_to_java(env, signerj, &signer);

    retArray = (*env)->NewObjectArray(env, n_signers,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    for (i = 0; i < n_signers; i++) {
        outArray = (*env)->NewByteArray(env, 32);
        (*env)->SetByteArrayRegion(env, outArray, 0, 32, (jbyte*)shares[i].data);
        (*env)->SetObjectArrayElement(env, retArray, i, outArray);
    }

    (void)classObject;

    return retArray;

}

JNIEXPORT void JNICALL Java_bitcoin_NativeSecp256k1_receive_1commitments
    (JNIEnv *env, jclass classObject, jobjectArray shares,
    jobject secretj, jobjectArray signerjs,
    jint index, jlong ctx_l) {

    struct signer *signers;
    struct signer_secrets secret;
    jbyte *b;
    int i, n_signers, threshold = 0;
    size_t j;
    jbyteArray * bytes;
    jobject current_signer = NULL;
    secp256k1_frost_share **shares_to_send;
    secp256k1_pubkey **pubcoeffs;
    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    n_signers = get_n_signers(env, signerjs);

    signers = (struct signer *) malloc(n_signers * sizeof(struct signer));
    shares_to_send = (secp256k1_frost_share **) malloc(n_signers * sizeof(secp256k1_frost_share *));
    pubcoeffs = (secp256k1_pubkey **) malloc(n_signers * sizeof(secp256k1_pubkey *));

    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));
    secret_java_to_c(env, secretj, &secret);

    for (i = 0; i < n_signers; i++) {
        shares_to_send[i] = (secp256k1_frost_share *) malloc(sizeof(secp256k1_frost_share));
        bytes = (jbyteArray * )(*env)->GetObjectArrayElement(env, shares, i);
        b = (jbyte * )(*env)->GetByteArrayElements(env, (jbyteArray) bytes, NULL);
        for (j = 0; j < 32; j++) {
            shares_to_send[i]->data[j] = b[j];
        }
    }
    for (i = 0; i < n_signers; i++) {
        signers[i] = *(struct signer *) malloc(sizeof(struct signer));
        bytes = (jobject * )(*env)->GetObjectArrayElement(env, signerjs, i);
        if (i == 0) {
            threshold = get_threshold(env, (jobject) bytes);
        }
        signer_java_to_c(env, (jobject) bytes, &signers[i]);
        if (i == index) {
            current_signer = (jobject) bytes;
        }
    }

    for (i = 0; i < n_signers; i++) {
        pubcoeffs[i] = signers[i].pubcoeff;
    }

    if(!secp256k1_frost_share_agg(ctx, &secret.agg_share, signers[index].vss_hash,
        (const secp256k1_frost_share *const *) shares_to_send,
        (const secp256k1_pubkey *const *) pubcoeffs, n_signers, threshold, index+1)) {
        printf("failed aggregating shares\n");
    }


    secret_c_to_java(env, secretj, &secret);
    signer_c_to_java(env, (jobject) current_signer, &signers[index]);


    (void)classObject;

}


JNIEXPORT jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_get_1combined_1public_1keys(JNIEnv *env, jclass classObject, jobjectArray publicKeys,  jint totalNumberOfKeys, jlong ctx_l)
{
    jbyteArray outArray;
    jbyteArray* bytes;
    jbyte *b;
    const size_t pubKeyLen = 64;
    int i;
    size_t j;
    secp256k1_xonly_pubkey **pub_key_ptr;
    secp256k1_xonly_pubkey agg_pk;

    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    pub_key_ptr = (secp256k1_xonly_pubkey **) malloc(totalNumberOfKeys * sizeof(secp256k1_xonly_pubkey *));
    for(i = 0; i < totalNumberOfKeys; i++)
    {
        pub_key_ptr[i] = (secp256k1_xonly_pubkey *) malloc(sizeof(secp256k1_xonly_pubkey));
        bytes = (jbyteArray *) (*env)->GetObjectArrayElement(env,publicKeys,i);
        b = (jbyte*) (*env)->GetByteArrayElements(env, (jbyteArray) bytes, NULL);
        for(j = 0; j < pubKeyLen; j++) {
            pub_key_ptr[i]->data[j] = (unsigned char) b[j];
        }
    }


    if(!secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pk, NULL, (const secp256k1_xonly_pubkey *const *) pub_key_ptr, totalNumberOfKeys)) {
        printf("FAILURE\n"); /*TODO throw java exception*/
    }


    outArray = (*env)->NewByteArray(env, pubKeyLen);
    (*env)->SetByteArrayRegion(env, outArray, 0, pubKeyLen, (jbyte*)agg_pk.data);

    (void)classObject;

    return outArray;
}

JNIEXPORT void JNICALL Java_bitcoin_NativeSecp256k1_send_1vss_1sign(JNIEnv *env, jclass classObject, jobject secretj, jobjectArray signersj, jobject sessionj, jobject cachej, jint index, jlong ctx_l) {
    struct signer *signers;
    struct signer_secrets secret;
    secp256k1_musig_session session;
    secp256k1_musig_keyagg_cache cache;

    int i, n_signers;
    jbyteArray * bytes;
    jobject current_signer = NULL;
    const secp256k1_xonly_pubkey **pubkeys;
    const secp256k1_musig_pubnonce **pubnonces;
    secp256k1_context *ctx;

    n_signers = get_n_signers(env, signersj);

    signers = (struct signer *) malloc(n_signers * sizeof(struct signer));
    pubkeys = (const secp256k1_xonly_pubkey **) malloc(n_signers * sizeof(secp256k1_xonly_pubkey *));
    pubnonces = (const secp256k1_musig_pubnonce **) malloc(n_signers * sizeof(secp256k1_musig_pubnonce *));

    ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));
    secret_java_to_c(env, secretj, &secret);


    session = *(secp256k1_musig_session *) malloc(sizeof(secp256k1_musig_session));
    session_java_to_c(env, sessionj, &session);

    cache = *(secp256k1_musig_keyagg_cache *) malloc(sizeof(secp256k1_musig_keyagg_cache));
    cache_java_to_c(env, cachej, &cache);

    for (i = 0; i < n_signers; i++) {
        signers[i] = *(struct signer *) malloc(sizeof(struct signer));
        bytes = (jobject * )(*env)->GetObjectArrayElement(env, signersj, i);
        signer_java_to_c(env, (jobject) bytes, &signers[i]);
        if (i == index) {
        current_signer = (jobject) bytes;
        }
    }

    for (i = 0; i < n_signers; i++) {
        pubkeys[i] = &signers[i].pubkey;
        pubnonces[i] = &signers[i].pubnonce;
    }


    if(!sign_vss_send(ctx, pubkeys, pubnonces, &secret, &signers[index], &cache,  &session, n_signers)) {
        printf("failed vss sign send\n");
    }

    secret_c_to_java(env, secretj, &secret);
    signer_c_to_java(env, current_signer, &signers[index]);
    session_c_to_java(env, sessionj, &session);
    cache_c_to_java(env, cachej, &cache);

    (void)classObject;
}

JNIEXPORT void JNICALL Java_bitcoin_NativeSecp256k1_receive_1vss_1sign(JNIEnv *env, jclass classObject, jobject signerj, jobject sessionj, jobject cachej, jlong ctx_l) {
    struct signer signer;
    secp256k1_context *ctx;

    secp256k1_musig_session session;
    secp256k1_musig_keyagg_cache cache;

    ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    signer = *(struct signer *) malloc(sizeof(struct signer));
    signer_java_to_c(env, signerj, &signer);

    session = *(secp256k1_musig_session *) malloc(sizeof(secp256k1_musig_session));
    session_java_to_c(env, sessionj, &session);

    cache = *(secp256k1_musig_keyagg_cache *) malloc(sizeof(secp256k1_musig_keyagg_cache));
    cache_java_to_c(env, cachej, &cache);

    if(!sign_vss_receive(ctx, &signer, &session, &cache)) {
    printf("failed receiving vss sign\n");/*TODO throw java exception*/
    }

    signer_c_to_java(env, signerj, &signer);
    session_c_to_java(env, sessionj, &session);
    cache_c_to_java(env, cachej, &cache);

    (void)classObject;
}

JNIEXPORT jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_aggregate_1vss_1sign(JNIEnv *env, jclass classObject, jobjectArray signersj, jobject sessionj, jlong ctx_l) {
    struct signer *signers;
    jbyteArray outArray;
    int i, n_signers;
    jbyteArray * bytes;
    const secp256k1_musig_partial_sig **partial_signs;
    unsigned char sig[64];
    secp256k1_musig_session session;

    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;
    session = *(secp256k1_musig_session *) malloc(sizeof(secp256k1_musig_session));
    session_java_to_c(env, sessionj, &session);

    n_signers = get_n_signers(env, signersj);

    partial_signs = (const secp256k1_musig_partial_sig **) malloc(n_signers * sizeof(secp256k1_musig_partial_sig *));
    signers = (struct signer *) malloc(n_signers * sizeof(struct signer));

    for (i = 0; i < n_signers; i++) {
        signers[i] = *(struct signer *) malloc(sizeof(struct signer));
        bytes = (jobject * )(*env)->GetObjectArrayElement(env, signersj, i);
        signer_java_to_c(env, (jobject) bytes, &signers[i]);
    }

    for (i = 0; i < n_signers; i++) {
        partial_signs[i] = &signers[i].partial_sig;
    }

    if(!partial_signs_aggregate(ctx, partial_signs, sig, &session, n_signers)) {
        printf("failed vss sign send\n");
    }

    for (i = 0; i < n_signers; i++) {
        bytes = (jobject * )(*env)->GetObjectArrayElement(env, signersj, i);
        signer_c_to_java(env, (jobject) bytes, &signers[i]);
    }


    session_c_to_java(env, sessionj, &session);

    outArray = (*env)->NewByteArray(env, 64);
    (*env)->SetByteArrayRegion(env, outArray, 0, 64, (jbyte*)sig);

    (void)classObject;

    return outArray;
}

JNIEXPORT jboolean JNICALL Java_bitcoin_NativeSecp256k1_verify_1vss_1sign(JNIEnv * env, jclass classObject, jbyteArray signature, jobject signerj, jbyteArray aggr_key, jlong ctx_l) {
    struct signer signer;
    secp256k1_context *ctx;

    jbyte *b;
    secp256k1_xonly_pubkey agg_pk;
    int j;

    unsigned char sig[64];

    ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    signer = *(struct signer *) malloc(sizeof(struct signer));
    signer_java_to_c(env, signerj, &signer);

    b = (jbyte * )(*env)->GetByteArrayElements(env, signature, NULL);
    for (j = 0; j < 64; j++) {
        sig[j] = b[j];
    }
    b = (jbyte * )(*env)->GetByteArrayElements(env, aggr_key, NULL);
    for (j = 0; j < 64; j++) {
        agg_pk.data[j] = b[j];
    }
    if (!secp256k1_schnorrsig_verify(ctx, sig, signer.vss_hash, 32, &agg_pk)) {
        printf("FAILED vss verify\n");
        return 0;
    }
    (void)classObject;
    return 1;
}


JNIEXPORT jobjectArray JNICALL Java_bitcoin_NativeSecp256k1_sign_1message_1first(JNIEnv * env, jclass classObject, jobject secretj, jobject signerj, jbyteArray msgj, jbyteArray sigj, jobject sessionj, jobject cachej, jlong ctx_l) {
    jbyteArray outArray;
    struct signer signer;
    struct signer_secrets secret;
    secp256k1_musig_session session;
    secp256k1_musig_keyagg_cache cache;

    jbyte *b;
    int j;
    unsigned char msg32[32];
    unsigned char sig64[64];

    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    signer = *(struct signer *) malloc(sizeof(struct signer));
    signer_java_to_c(env, signerj, &signer);

    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));
    secret_java_to_c(env, secretj, &secret);

    session = *(secp256k1_musig_session *) malloc(sizeof(secp256k1_musig_session));
    session_java_to_c(env, sessionj, &session);

    cache = *(secp256k1_musig_keyagg_cache *) malloc(sizeof(secp256k1_musig_keyagg_cache));
    cache_java_to_c(env, cachej, &cache);


    b = (jbyte * )(*env)->GetByteArrayElements(env, sigj, NULL);
    for (j = 0; j < 64; j++) {
        sig64[j] = b[j];
    }
    b = (jbyte * )(*env)->GetByteArrayElements(env, msgj, NULL);
    for (j = 0; j < 32; j++) {
        msg32[j] = b[j];
    }

    if (!sign_message_step0(ctx, &secret, &signer, msg32)) {
        printf("failed signing message - step 0");
    }
    signer_c_to_java(env, signerj, &signer);
    session_c_to_java(env, sessionj, &session);
    cache_c_to_java(env, cachej, &cache);
    secret_c_to_java(env, secretj, &secret);

    outArray = (*env)->NewByteArray(env, 64);
    (*env)->SetByteArrayRegion(env, outArray, 0, 64, (jbyte*)sig64);
    (void)classObject;
    return outArray;
}


JNIEXPORT jboolean JNICALL Java_bitcoin_NativeSecp256k1_verify_1frost(JNIEnv * env, jclass classObject, jbyteArray sigj, jbyteArray msgj, jbyteArray keyj, jlong ctx_l) {

    jbyte *b;
    int j;
    unsigned char msg32[32];
    unsigned char sig64[64];
    secp256k1_xonly_pubkey agg_pk;

    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    b = (jbyte * )(*env)->GetByteArrayElements(env, sigj, NULL);
    for (j = 0; j < 64; j++) {
        sig64[j] = b[j];
    }
    b = (jbyte * )(*env)->GetByteArrayElements(env, msgj, NULL);
    for (j = 0; j < 32; j++) {
        msg32[j] = b[j];
    }
    b = (jbyte * )(*env)->GetByteArrayElements(env, keyj, NULL);
    for (j = 0; j < 64; j++) {
        agg_pk.data[j] = b[j];
    }

    if (!secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, &agg_pk)) {
        printf("FAILED verify\n");
        return 0;
    }
    (void)classObject;
    return 1;
}

JNIEXPORT void JNICALL Java_bitcoin_NativeSecp256k1_sign_1message_1second(JNIEnv * env, jclass classObject, jintArray jparticipants, jobject secretj, jobjectArray signersj, jbyteArray msgj, jobject sessionj, jobject cachej,jint index, jlong ctx_l) {
    struct signer *signers;
    struct signer_secrets secret;
    secp256k1_musig_session session;
    secp256k1_musig_keyagg_cache cache;
    size_t *participants;
    jobject current_signer = NULL;
    jbyte *b;

    int i, j, n_signers, threshold = 0;
    jbyteArray *bytes;
    unsigned char msg32[32];
    secp256k1_musig_pubnonce **pubnonces;
    secp256k1_xonly_pubkey **pubkeys;
    jint* myint;

    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));
    secret_java_to_c(env, secretj, &secret);

    session = *(secp256k1_musig_session *) malloc(sizeof(secp256k1_musig_session));
    session_java_to_c(env, sessionj, &session);

    cache = *(secp256k1_musig_keyagg_cache *) malloc(sizeof(secp256k1_musig_keyagg_cache));
    cache_java_to_c(env, cachej, &cache);

    n_signers = get_n_signers(env, signersj);

    signers = (struct signer *) malloc(n_signers * sizeof(struct signer));
    pubnonces = (secp256k1_musig_pubnonce **) malloc(n_signers * sizeof(secp256k1_musig_pubnonce *));
    pubkeys = (secp256k1_xonly_pubkey **) malloc(n_signers * sizeof(secp256k1_xonly_pubkey *));

    for (i = 0; i < n_signers; i++) {
        signers[i] = *(struct signer *) malloc(sizeof(struct signer));
        bytes = (jobject * )(*env)->GetObjectArrayElement(env, signersj, i);
        signer_java_to_c(env, (jobject) bytes, &signers[i]);
        if (i == index) {
            current_signer = (jobject) bytes;
            threshold = get_threshold(env, (jobject) bytes);
        }
    }

    participants = (size_t *) malloc(threshold * sizeof(size_t));

    for (i = 0; i < n_signers; i++) {
        pubkeys[i] = &signers[i].pubkey;
        pubnonces[i] = &signers[i].pubnonce;
    }

    b = (jbyte * )(*env)->GetByteArrayElements(env, msgj, NULL);
    for (j = 0; j < 32; j++) {
        msg32[j] = b[j];
    }

    myint = (jint * )(*env)->GetIntArrayElements(env, jparticipants, NULL);
    for (j = 0; j < threshold; j++) {
        participants[j] = myint[j];
    }

    if (!sign_message_step1(ctx, &secret, &signers[index], msg32, pubkeys, pubnonces, participants, index, &session, &cache, n_signers, threshold)) {
        printf("failed signing message - step 1");
    }

    signer_c_to_java(env, current_signer, &signers[index]);
    session_c_to_java(env, sessionj, &session);
    cache_c_to_java(env, cachej, &cache);
    secret_c_to_java(env, secretj, &secret);
    (void)classObject;
}


JNIEXPORT jbyteArray JNICALL Java_bitcoin_NativeSecp256k1_sign_1message_1third(JNIEnv * env, jclass classObject, jbyteArray sigj, jobjectArray signersj, jobject sessionj, jlong ctx_l) {
    jbyteArray outArray;
    struct signer *signers;
    secp256k1_musig_session session;
    unsigned char sig64[64];

    const secp256k1_musig_partial_sig **partial_sigs;
    jbyte *b;
    int i, j, n_signers, threshold = 0;
    jbyteArray *bytes;

    secp256k1_context *ctx = (secp256k1_context *)(uintptr_t) ctx_l;

    session = *(secp256k1_musig_session *) malloc(sizeof(secp256k1_musig_session));
    session_java_to_c(env, sessionj, &session);

    n_signers = get_n_signers(env, signersj);

    signers = (struct signer *) malloc(n_signers * sizeof(struct signer));
    partial_sigs = (const secp256k1_musig_partial_sig **) malloc(n_signers * sizeof(secp256k1_musig_partial_sig *));

    for (i = 0; i < n_signers; i++) {
        signers[i] = *(struct signer *) malloc(sizeof(struct signer));
        bytes = (jobject * )(*env)->GetObjectArrayElement(env, signersj, i);
        signer_java_to_c(env, (jobject) bytes, &signers[i]);
        if (i == 0) {
            threshold = get_threshold(env, (jobject) bytes);
        }
    }

    for (i = 0; i < threshold; i++) {
        partial_sigs[i] = &signers[i].partial_sig;
    }

    b = (jbyte * )(*env)->GetByteArrayElements(env, sigj, NULL);
    for (j = 0; j < 64; j++) {
        sig64[j] = b[j];
    }

    if (!secp256k1_musig_partial_sig_agg(ctx, sig64, &session, partial_sigs, threshold)) {
        printf("failed signing message - step 3");
    }
    outArray = (*env)->NewByteArray(env, 64);
    (*env)->SetByteArrayRegion(env, outArray, 0, 64, (jbyte*)sig64);
    (void)classObject;
    return outArray;
}

