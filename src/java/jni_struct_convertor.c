//
// Created by Ioana Savu on 3/14/22.
//
#include "examples/frost.c"
#include <jni.h>

int secret_java_to_c(JNIEnv *env, jobject jsecret, struct signer_secrets *secret) {
    jfieldID fid;
    jbyteArray bytes;
    jbyte *b;
    jclass secret_class;
    int i;
    int j;

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
    jbyteArray bytes;
    jbyte *b;
    secret_class = (*env)->GetObjectClass(env, jsecret);

    fid = (*env)->GetFieldID(env, secret_class, "keypair", "[B");
    jbyteArray jBuff = (*env)->NewByteArray(env, 96);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 96, secret->keypair.data);
    (*env)->SetObjectField(env, jsecret, fid, jBuff);
//    (*env)->ReleaseByteArrayElements(env, jBuff, &secret.keypair.data, 0);


    fid = (*env)->GetFieldID(env, secret_class, "agg_share", "[B");
    jBuff = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 32, secret->agg_share.data);
    (*env)->SetObjectField(env, jsecret, fid, jBuff);
//    (*env)->ReleaseByteArrayElements(env, jBuff, &secret.agg_share.data, 0);


    fid = (*env)->GetFieldID(env, secret_class, "secnonce", "[B");
    jBuff = (*env)->NewByteArray(env, 68);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 68, secret->secnonce.data);
    (*env)->SetObjectField(env, jsecret, fid, jBuff);
//    (*env)->ReleaseByteArrayElements(env, jBuff, &secret.secnonce.data, 0);
    return 0;
}

int signer_java_to_c(JNIEnv *env, jobject jsigner, struct signer *signer) {
    jfieldID fid;
    jbyteArray bytes;
    jbyte *b;
    jobjectArray pubcoeff;
    jclass signer_class;
    int i;
    int j;

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
    jbyteArray* bytes2;
    for (i = 0; i < THRESHOLD; i++) {
        bytes2 = (jbyteArray * ) (*env)->GetObjectArrayElement(env, pubcoeff, i);
        b = (jbyte * )(*env)->GetByteArrayElements(env, bytes2, NULL);
        signer->pubcoeff[i] = *(secp256k1_pubkey *) malloc(sizeof(secp256k1_pubkey));
        for (j = 0; j < 64; j++) {
            signer->pubcoeff[i].data[j] = b[j];
        }
        (*env)->ReleaseByteArrayElements(env, bytes2, b, 0);
    }
    return 0;
}


int signer_c_to_java(JNIEnv *env, jobject jsigner, struct signer *signer) {
    jfieldID fid;
    jbyteArray bytes;
    jbyte *b;
    jobjectArray pubcoeff;
    jclass signer_class;
    int i;
    int j;

    signer_class = (*env)->GetObjectClass(env, jsigner);

    fid = (*env)->GetFieldID(env, signer_class, "pubkey", "[B");
    jbyteArray jBuff = (*env)->NewByteArray(env, 64);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 64, signer->pubkey.data);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);
//    (*env)->ReleaseByteArrayElements(env, jBuff, &signer.pubkey.data, 0);


    fid = (*env)->GetFieldID(env, signer_class, "pubnonce", "[B");
    jBuff = (*env)->NewByteArray(env, 132);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 132, signer->pubnonce.data);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);
//    (*env)->ReleaseByteArrayElements(env, jBuff, &signer.pubnonce.data, 0);


    fid = (*env)->GetFieldID(env, signer_class, "partial_sig", "[B");
    jBuff = (*env)->NewByteArray(env, 36);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 36, signer->partial_sig.data);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);
//    (*env)->ReleaseByteArrayElements(env, jBuff, &signer.partial_sig.data, 0);

    fid = (*env)->GetFieldID(env, signer_class, "vss_hash", "[B");
    jBuff = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, jBuff, 0, 32, signer->vss_hash);
    (*env)->SetObjectField(env, jsigner, fid, jBuff);
//    (*env)->ReleaseByteArrayElements(env, jBuff, &signer.vss_hash, 0);

    fid = (*env)->GetFieldID(env, signer_class, "pubcoeff", "[[B");
    jclass myClassArray = (*env)->FindClass(env, "[B");

    jobjectArray in = (*env)->NewObjectArray(env,THRESHOLD,myClassArray,NULL);
    for(i = 0; i < THRESHOLD; i++) {
        jBuff = (*env)->NewByteArray(env, 64);
        (*env)->SetByteArrayRegion(env, jBuff, 0, 64, signer->pubcoeff[i].data);
        (*env)->SetObjectArrayElement(env, in, i, jBuff);
//        (*env)->ReleaseByteArrayElements(env, jBuff, &signer.pubcoeff[i].data, 0);
    }
    (*env)->SetObjectField(env, jsigner, fid, in);

    return 0;
}

