#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "org_bitcoin_NativeSecp256k1.h"
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_recovery.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include <secp256k1_frost.h>
#include <stdio.h>
#include "jni_struct_convertor.c"

#define N_SIGNERS 5
#define THRESHOLD 3
#define ONE 1

/*struct signer_secrets {
    secp256k1_keypair keypair;
    secp256k1_frost_share agg_share;
    secp256k1_musig_secnonce secnonce;
};

struct signer {
    secp256k1_xonly_pubkey pubkey;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_musig_partial_sig partial_sig;
    secp256k1_pubkey pubcoeff[THRESHOLD];
    unsigned char vss_hash[32];
};*/

/* Create shares and coefficient commitments */
int send_shares(const secp256k1_context* ctx,
                secp256k1_frost_share shares[N_SIGNERS],
                const secp256k1_xonly_pubkey *pubkeys[N_SIGNERS],
                struct signer_secrets signer_secret, struct signer *signer) {
    /* The same for all signers */
    secp256k1_musig_keyagg_cache cache;

    FILE *frand;
    unsigned char seckey[32];
    unsigned char session_id[32];
    /* Create random session ID. It is absolutely necessary that the session ID
     * is unique for every call of secp256k1_musig_nonce_gen. Otherwise
     * it's trivial for an attacker to extract the secret key! */
    frand = fopen("/dev/urandom", "r");
    if(frand == NULL) {
        return 0;
    }
    if (!fread(session_id, 32, 1, frand)) {
        fclose(frand);
        printf("failed here 0000\n");
        return 0;
    }
    fclose(frand);
    if (!secp256k1_keypair_sec(ctx, seckey, &signer_secret.keypair)) {
        printf("failed here 0\n");
        return 0;
    }
    /* Initialize session and create secret nonce for signing and public
     * nonce to send to the other signers. */
    if (!secp256k1_musig_nonce_gen(ctx, &signer_secret.secnonce, &signer->pubnonce, session_id, seckey, NULL, NULL, NULL)) {
        printf("failed here 1\n");
        return 0;
    }

    if (!secp256k1_musig_pubkey_agg(ctx, NULL, NULL, &cache, pubkeys, N_SIGNERS)) {
        printf("failed here 2\n");
        return 0;
    }
    /* Generate a polynomial share for each participant */
    if (!secp256k1_frost_share_gen(ctx, signer->pubcoeff, shares, THRESHOLD, N_SIGNERS, &signer_secret.keypair, &cache)) {
        printf("failed here 3\n");
        return 0;
    }
    return 1;
}

/* Create shares and coefficient commitments */
int receive_shares(const secp256k1_context* ctx, const secp256k1_pubkey *pubcoeffs[N_SIGNERS],
                   const secp256k1_frost_share shares[N_SIGNERS], struct signer_secrets *signer_secret,
                           struct signer *signer, int index) {

    /* KeyGen communication round 1: exchange shares, nonce commitments, and
     * coefficient commitments */

    /* Each participant receives a share from each participant (including
     * themselves) corresponding to their index. */

    /* Each participant aggregates the shares they received. */
    if (!secp256k1_frost_share_agg(ctx, &(*signer_secret).agg_share, (*signer).vss_hash,
                                   &shares, pubcoeffs, N_SIGNERS, THRESHOLD, index+1)) {
        return 0;
    }

    return 1;
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
    FILE *frand = fopen("/dev/urandom", "r");
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


SECP256K1_API jlong JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ctx_1clone
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  const secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

  jlong ctx_clone_l = (uintptr_t) secp256k1_context_clone(ctx);

  (void)classObject;(void)env;

  return ctx_clone_l;

}

SECP256K1_API jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1context_1randomize
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

  const unsigned char* seed = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_context_randomize(ctx, seed);

}

SECP256K1_API void JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1destroy_1context
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

  secp256k1_context_destroy(ctx);

  (void)classObject;(void)env;
}

SECP256K1_API jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
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

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign
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

SECP256K1_API jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1seckey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_ec_seckey_verify(ctx, secKey);
}

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1create
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

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1add
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

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1mul
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

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1add
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

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1mul
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

SECP256K1_API jlong JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1pubkey_1combine
  (JNIEnv * env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint numkeys)
{
  (void)classObject;(void)env;(void)byteBufferObject;(void)ctx_l;(void)numkeys;

  return 0;
}

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdh
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


JNIEXPORT void JNICALL Java_org_bitcoin_NativeSecp256k1_generate_1key(JNIEnv * env, jclass classObject,
        jobject secretj, jobject signerj, jlong ctx_l) {
    struct signer signer;
    struct signer_secrets secret;
    secp256k1_context *ctx;
    int i;

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

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_send_1shares(JNIEnv * env, jclass classObject, jobjectArray public_keys, jobject secretj, jobject signerj, jlong ctx_l) {
    struct signer signer;
    struct signer_secrets secret;
    jbyteArray * bytes;
    jbyteArray outArray;
    jobjectArray retArray;
    jbyte *b;
    int i;
    size_t j;
    secp256k1_xonly_pubkey *pub_key_ptr[N_SIGNERS];

    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    for (i = 0; i < N_SIGNERS; i++) {
        pub_key_ptr[i] = (secp256k1_xonly_pubkey *) malloc(sizeof(secp256k1_xonly_pubkey));
        bytes = (jbyteArray * )(*env)->GetObjectArrayElement(env, public_keys, i);
        b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
        for (j = 0; j < 64; j++) {
            pub_key_ptr[i]->data[j] = (unsigned char) b[j];
        }
    }

    signer = *(struct signer *) malloc(sizeof(struct signer));
    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));

    secret_java_to_c(env, secretj, &secret);
    signer_java_to_c(env, signerj, &signer);

    secp256k1_frost_share shares[N_SIGNERS];

    if(!send_shares(ctx, shares, pub_key_ptr, secret, &signer)) {
        printf("FAILURE\n"); /*TODO throw java exception*/
    }

    secret_c_to_java(env, secretj, &secret);
    signer_c_to_java(env, signerj, &signer);

    retArray = (*env)->NewObjectArray(env, N_SIGNERS,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    for (i = 0; i < N_SIGNERS; i++) {
        outArray = (*env)->NewByteArray(env, 32);
        (*env)->SetByteArrayRegion(env, outArray, 0, 32, (jbyte*)shares[i].data);
        (*env)->SetObjectArrayElement(env, retArray, i, outArray);
    }

    (void)classObject;

    return retArray;

}




/*
 * Class:     org_bitcoin_NativeSecp256k1
 * Method:    generate_key_pair
 * Signature: ()[[B
 */
JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_generate_1key_1pair(JNIEnv *env, jclass classObject, jlong ctx_l)
{
    jobjectArray retArray;
    jbyteArray pubKeyArray, keyPairArray;
    secp256k1_xonly_pubkey pubkey;
    secp256k1_keypair keypair;
    secp256k1_context *ctx;

    size_t pubKeyLen = 64;
    size_t keyPairLen = 96;


    ctx = (secp256k1_context*)(uintptr_t)ctx_l;
    if(!create_key_pair_java(ctx, &pubkey, &keypair)) {
        printf("failure\n");/*TODO throw java exception*/
    }

    /*Return public key and keypair*/
    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));


    keyPairArray = (*env)->NewByteArray(env, keyPairLen);
    (*env)->SetByteArrayRegion(env, keyPairArray, 0, keyPairLen, (jbyte*)keypair.data);
    (*env)->SetObjectArrayElement(env, retArray, 0, keyPairArray);

    pubKeyArray = (*env)->NewByteArray(env, pubKeyLen);
    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKeyLen, (jbyte*)pubkey.data);
    (*env)->SetObjectArrayElement(env, retArray, 1, pubKeyArray);

    (void)classObject;

    return retArray;
}



JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_get_1combined_1public_1keys(JNIEnv *env, jclass classObject, jobjectArray publicKeys,  jint totalNumberOfKeys, jlong ctx_l)
{
    jbyteArray outArray;
    jbyteArray* bytes;
    jbyte *b;
    const size_t pubKeyLen = 64;
    int i;
    size_t j;
    secp256k1_xonly_pubkey *pub_key_ptr[5];
    secp256k1_xonly_pubkey agg_pk;

    secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

    for(i = 0; i < totalNumberOfKeys; i++)
    {
        pub_key_ptr[i] = (secp256k1_xonly_pubkey *) malloc(sizeof(secp256k1_xonly_pubkey));
        bytes = (jbyteArray *) (*env)->GetObjectArrayElement(env,publicKeys,i);
        b = (jbyte*) (*env)->GetByteArrayElements(env, bytes, NULL);
        for(j = 0; j < pubKeyLen; j++) {
            pub_key_ptr[i]->data[j] = (unsigned char) b[j];
        }
    }


    if(!secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pk, NULL, pub_key_ptr, totalNumberOfKeys)) {
        printf("FAILURE\n"); /*TODO throw java exception*/
    }

    outArray = (*env)->NewByteArray(env, pubKeyLen);
    (*env)->SetByteArrayRegion(env, outArray, 0, pubKeyLen, (jbyte*)agg_pk.data);

    (void)classObject;

    return outArray;
}
//
//JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_create_1commitments
//        (JNIEnv *env, jclass classObject, jobjectArray public_keys, jbyteArray key_pair, jlong ctx_l) {
//
//    jbyteArray outArray;
//    jobjectArray retArray;
//    jbyteArray * bytes;
//    jbyte *b;
//    const size_t pubKeyLen = 64;
//    int i;
//    size_t j;
//    secp256k1_xonly_pubkey *pub_key_ptr[5];
//
//    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;
//
//    for (i = 0; i < 5; i++) {
//        pub_key_ptr[i] = (secp256k1_xonly_pubkey *) malloc(sizeof(secp256k1_xonly_pubkey));
//        bytes = (jbyteArray * )(*env)->GetObjectArrayElement(env, public_keys, i);
//        b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
//        for (j = 0; j < pubKeyLen; j++) {
//            pub_key_ptr[i]->data[j] = (unsigned char) b[j];
//        }
//    }
//    struct signer_secrets* secret = (struct signer_secrets*) malloc(sizeof(struct signer_secrets));
//    b = (jbyte * )(*env)->GetByteArrayElements(env, key_pair, NULL);
//    secret->keypair = *(secp256k1_keypair*) malloc(sizeof(secp256k1_keypair));
//    for (i = 0; i < 96; i++) {
//        secret->keypair.data[i] = b[i];
//    }
//    /*b = (jbyte * )(*env)->GetByteArrayElements(env, sec_nonce, NULL);
//    secret->secnonce = (secp256k1_musig_secnonce) malloc(sizeof(secp256k1_musig_secnonce));*/
//
//    struct signer* signer = (struct signer*) malloc(sizeof(struct signer));
//    /*signer->pubnonce = (secp256k1_musig_pubnonce) malloc(sizeof(secp256k1_musig_pubnonce));
//
//    for (i = 0; i < THRESHOLD; i++) {
//        signer->pubcoeff[i] = (secp256k1_pubkey) malloc(sizeof(secp256k1_pubkey));
//    }*/
//    secp256k1_frost_share shares[N_SIGNERS];
//
//    if(!send_shares(ctx, shares, pub_key_ptr, *secret, signer)) {
//        printf("FAILURE\n"); /*TODO throw java exception*/
//    }
//
//
//    retArray = (*env)->NewObjectArray(env, N_SIGNERS + THRESHOLD,
//                                      (*env)->FindClass(env, "[B"),
//                                      (*env)->NewByteArray(env, 1));
//
//    for (i = 0; i < N_SIGNERS; i++) {
//        outArray = (*env)->NewByteArray(env, 32);
//        (*env)->SetByteArrayRegion(env, outArray, 0, 32, (jbyte*)shares[i].data);
//        (*env)->SetObjectArrayElement(env, retArray, i, outArray);
//    }
//
//    for (i = 0; i < THRESHOLD; i++) {
//        outArray = (*env)->NewByteArray(env, 64);
//        (*env)->SetByteArrayRegion(env, outArray, 0, 64, (jbyte*)signer->pubcoeff[i].data);
//        (*env)->SetObjectArrayElement(env, retArray, i + N_SIGNERS, outArray);
//    }
//
//
//    (void)classObject;
//
//    return retArray;
//}

JNIEXPORT void JNICALL Java_org_bitcoin_NativeSecp256k1_receive_1commitments
        (JNIEnv *env, jclass classObject, jobjectArray shares,
         jobject secretj, jobjectArray signerjs,
         jint index, jlong ctx_l) {

    struct signer signers[N_SIGNERS];
    struct signer_secrets secret;
    jbyte *b;
    int i;
    size_t j;
    jbyteArray * bytes;
    jobject bytes2;
    jobject current_signer;
    secp256k1_frost_share* shares_to_send[N_SIGNERS];
    secp256k1_pubkey *pubcoeffs[N_SIGNERS];
    secp256k1_context *ctx = (secp256k1_context *) (uintptr_t) ctx_l;

    secret = *(struct signer_secrets *) malloc(sizeof(struct signer_secrets));
    secret_java_to_c(env, secretj, &secret);

    for (i = 0; i < N_SIGNERS; i++) {
        shares_to_send[i] = (secp256k1_frost_share *) malloc(sizeof(secp256k1_frost_share));
        bytes = (jbyteArray * )(*env)->GetObjectArrayElement(env, shares, i);
        b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
        for (j = 0; j < 32; j++) {
            shares_to_send[i]->data[j] = &b[j];
        }
    }

    for (i = 0; i < N_SIGNERS; i++) {
        signers[i] = *(struct signer *) malloc(sizeof(struct signer));
        bytes = (jobject * )(*env)->GetObjectArrayElement(env, signerjs, i);
        signer_java_to_c(env, bytes, &signers[i]);
        if (i == index) {
            current_signer = bytes;
        }
    }

    for (i = 0; i < N_SIGNERS; i++) {
        pubcoeffs[i] = signers[i].pubcoeff;
    }
    for (i = 0; i < 32; i++) {
    printf("%d, ", secret.agg_share.data[i]);
    }
    if(!secp256k1_frost_share_agg(ctx, &secret.agg_share, signers[index].vss_hash,
            shares_to_send, pubcoeffs, N_SIGNERS, THRESHOLD, index+1)) {
        printf("failed aggregating shares\n");
    }

    printf("\naaaaa\n");

    secret_c_to_java(env, secretj, &secret);
    signer_c_to_java(env, current_signer, &signers[index]);



    (void)classObject;

}

/*secp256k1_musig_partial_sig secp256k1_frost_partial_sign_java(secp256k1_context* ctx, secp256k1_musig_session session, struct signer currentSigner,const unsigned char* msg32, size_t number_of_participants, size_t current_index)
//{
//
//    size_t participants[number_of_participants];
//    / Set indexes of participants who will be signing /
//    int i;
//    for (i = 0; i < number_of_participants; i++) {
//        participants[i] = i+1;
//    }
//
//    secp256k1_musig_aggnonce agg_pubnonce;
//
//    / Create aggregate pubkey, aggregate nonce and initialize signer data /
//    if (!secp256k1_musig_pubkey_agg(ctx, NULL, NULL, &cache, pubkeys, N_SIGNERS)) {
//        return 0;
//    }
//    if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, THRESHOLD)) {
//        return 0;
//    }
//    if (!secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, msg32, &cache, NULL)) {
//        return 0;
//    }
//    / partial_sign will clear the secnonce by setting it to 0. That's because
//      you must _never_ reuse the secnonce (or use the same session_id to
//      create a secnonce). If you do, you effectively reuse the nonce and
//      leak the secret key. /
//    if (!secp256k1_frost_partial_sign(ctx, &currentSigner.partial_sig, &currentSigner.secnonce, &currentSigner.agg_share, &session, number_of_participants, participants, current_index)) {
//        return 0;
//    }
//    return signer.partial_sig;
//}*/

