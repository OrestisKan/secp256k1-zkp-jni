#include "examples/frost.c"
#include <jni.h>

int session_java_to_c(JNIEnv *env, jobject jsession, secp256k1_musig_session *session) {
    jfieldID fid;
    jbyteArray bytes;
    jbyte *b;
    jclass session_class;
    int i;
    session_class = (*env)->GetObjectClass(env, jsession);

    fid = (*env)->GetFieldID(env, session_class, "session", "[B");
    bytes = (*env)->GetObjectField(env, jsession, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);

    for (i = 0; i < 133; i++) {
        session->data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    return 1;
}

int session_c_to_java(JNIEnv *env, jobject jsession, secp256k1_musig_session *session) {
    jfieldID fid;
    jclass session_class;
    jbyteArray jBuff;

    session_class = (*env)->GetObjectClass(env, jsession);

    fid = (*env)->GetFieldID(env, session_class, "session", "[B");
    jBuff = (*env)->NewByteArray(env, 133);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 133, (const signed char *) session->data);
    (*env)->SetObjectField(env, jsession, fid, jBuff);
    return 1;
}

int cache_java_to_c(JNIEnv *env, jobject jcache, secp256k1_musig_keyagg_cache *cache) {
    jfieldID fid;
    jbyteArray bytes;
    jbyte *b;
    jclass cache_class;
    int i;
    cache_class = (*env)->GetObjectClass(env, jcache);

    fid = (*env)->GetFieldID(env, cache_class, "cache", "[B");
    bytes = (*env)->GetObjectField(env, jcache, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);

    for (i = 0; i < 165; i++) {
        cache->data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);
    return 1;
}

int cache_c_to_java(JNIEnv *env, jobject jcache, secp256k1_musig_keyagg_cache *cache) {
    jfieldID fid;
    jclass cache_class;
    jbyteArray jBuff;
    cache_class = (*env)->GetObjectClass(env, jcache);

    fid = (*env)->GetFieldID(env, cache_class, "cache", "[B");
    jBuff = (*env)->NewByteArray(env, 165);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 165, (const signed char *) cache->data);
    (*env)->SetObjectField(env, jcache, fid, jBuff);

    return 1;
}
int secret_java_to_c(JNIEnv *env, jobject jsecret, struct signer_secrets *secret) {
    jfieldID fid;
    jbyteArray bytes;
    jbyte *b;
    jclass secret_class;
    int i;

    secret_class = (*env)->GetObjectClass(env, jsecret);

    fid = (*env)->GetFieldID(env, secret_class, "keypair", "[B");
    bytes = (*env)->GetObjectField(env, jsecret, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);

    for (i = 0; i < 96; i++) {
        secret->keypair.data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    fid = (*env)->GetFieldID(env, secret_class, "agg_share", "[B");
    bytes = (*env)->GetObjectField(env, jsecret, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);

    for (i = 0; i < 32; i++) {
        secret->agg_share.data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    fid = (*env)->GetFieldID(env, secret_class, "secnonce", "[B");
    bytes = (*env)->GetObjectField(env, jsecret, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
    for (i = 0; i < 68; i++) {
        secret->secnonce.data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    return 0;
}

int secret_c_to_java(JNIEnv *env, jobject jsecret, struct signer_secrets *secret) {
    jfieldID fid;
    jclass secret_class;
    jbyteArray jBuff;
    secret_class = (*env)->GetObjectClass(env, jsecret);

    fid = (*env)->GetFieldID(env, secret_class, "keypair", "[B");
    jBuff = (*env)->NewByteArray(env, 96);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 96, (const signed char *) secret->keypair.data);
    (*env)->SetObjectField(env, jsecret, fid, jBuff);


    fid = (*env)->GetFieldID(env, secret_class, "agg_share", "[B");
    jBuff = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 32, (const signed char *) secret->agg_share.data);
    (*env)->SetObjectField(env, jsecret, fid, jBuff);


    fid = (*env)->GetFieldID(env, secret_class, "secnonce", "[B");
    jBuff = (*env)->NewByteArray(env, 68);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 68, (const signed char *) secret->secnonce.data);
    (*env)->SetObjectField(env, jsecret, fid, jBuff);
    return 0;
}

int get_threshold(JNIEnv *env, jobject jsigner) {
    jfieldID fid;
    jobjectArray pubcoeff;
    jclass signer_class;
    int threshold;

    signer_class = (*env)->GetObjectClass(env, jsigner);
    fid = (*env)->GetFieldID(env, signer_class, "pubcoeff", "[[B");
    pubcoeff = (*env)->GetObjectField(env, jsigner, fid);
    threshold = (*env)->GetArrayLength(env, pubcoeff);

    return threshold;
}

int get_n_signers(JNIEnv *env, jobjectArray jarr) {
    int N;
    N = (*env)->GetArrayLength(env, jarr);
    return N;
}

int signer_java_to_c(JNIEnv *env, jobject jsigner, struct signer *signer) {
    int i, j;
    int threshold;
    jfieldID fid;
    jbyteArray bytes;
    jbyte *b;
    jobjectArray pubcoeff;
    jclass signer_class;
    jbyteArray* bytes2;

    signer_class = (*env)->GetObjectClass(env, jsigner);

    fid = (*env)->GetFieldID(env, signer_class, "pubkey", "[B");
    bytes = (*env)->GetObjectField(env, jsigner, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
    for (i = 0; i < 64; i++) {
        signer->pubkey.data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    fid = (*env)->GetFieldID(env, signer_class, "pubnonce", "[B");
    bytes = (*env)->GetObjectField(env, jsigner, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
    for (i = 0; i < 132; i++) {
        signer->pubnonce.data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    fid = (*env)->GetFieldID(env, signer_class, "partial_sig", "[B");
    bytes = (*env)->GetObjectField(env, jsigner, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
    for (i = 0; i < 36; i++) {
        signer->partial_sig.data[i] = b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    fid = (*env)->GetFieldID(env, signer_class, "vss_hash", "[B");
    bytes = (*env)->GetObjectField(env, jsigner, fid);
    b = (jbyte * )(*env)->GetByteArrayElements(env, bytes, NULL);
    for (i = 0; i < 32; i++) {
        signer->vss_hash[i] = (unsigned char) b[i];
    }
    (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

    fid = (*env)->GetFieldID(env, signer_class, "pubcoeff", "[[B");
    pubcoeff = (*env)->GetObjectField(env, jsigner, fid);

    threshold = get_threshold(env, jsigner);

    for (i = 0; i < threshold; i++) {
        bytes2 = (jbyteArray * ) (*env)->GetObjectArrayElement(env, pubcoeff, i);
        b = (jbyte * )(*env)->GetByteArrayElements(env, (jbyteArray) bytes2, NULL);
        signer->pubcoeff[i] = *(secp256k1_pubkey *) malloc(sizeof(secp256k1_pubkey));
        for (j = 0; j < 64; j++) {
            signer->pubcoeff[i].data[j] = b[j];
        }
        (*env)->ReleaseByteArrayElements(env, (jbyteArray) bytes2, b, 0);
    }
    return 0;
}


int signer_c_to_java(JNIEnv *env, jobject jsigner, struct signer *signer) {
    int i;
    int threshold;
    jfieldID fid;
    jclass signer_class;
    jbyteArray jBuff;
    jobjectArray in;
    jclass myClassArray;

    signer_class = (*env)->GetObjectClass(env, jsigner);
    fid = (*env)->GetFieldID(env, signer_class, "pubkey", "[B");
    jBuff = (*env)->NewByteArray(env, 64);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 64, (const signed char *) signer->pubkey.data);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);

    fid = (*env)->GetFieldID(env, signer_class, "pubnonce", "[B");
    jBuff = (*env)->NewByteArray(env, 132);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 132, (const signed char *) signer->pubnonce.data);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);

    fid = (*env)->GetFieldID(env, signer_class, "partial_sig", "[B");
    jBuff = (*env)->NewByteArray(env, 36);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 36, (const signed char *) signer->partial_sig.data);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);

    fid = (*env)->GetFieldID(env, signer_class, "vss_hash", "[B");
    jBuff = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 32, (const signed char *) signer->vss_hash);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);

    fid = (*env)->GetFieldID(env, signer_class, "pubcoeff", "[[B");
    myClassArray = (*env)->FindClass(env, "[B");

    threshold = get_threshold(env, jsigner);
    in = (*env)->NewObjectArray(env,threshold,myClassArray,NULL);
    for(i = 0; i < threshold; i++) {
        jBuff = (*env)->NewByteArray(env, 64);
        (*env)->SetByteArrayRegion(env, jBuff, 0, 64, (const signed char *) signer->pubcoeff[i].data);
        (*env)->SetObjectArrayElement(env, in, i, jBuff);
    }
    (*env)->SetObjectField(env, jsigner, fid, in);

    return 0;
}

