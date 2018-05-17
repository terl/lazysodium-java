/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.interfaces.GenericHash;
import com.goterl.lazycode.lazysodium.interfaces.SecretStream;

public class Sodium {

    public Sodium() {

    }

    //// -------------------------------------------|
    //// PADDING
    //// -------------------------------------------|
    native int sodium_pad(int paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize, int maxBufLen);

    native int sodium_unpad(int paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize);


    //// -------------------------------------------|
    //// RANDOM
    //// -------------------------------------------|
    native byte randombytes_random();

    native byte randombytes_uniform(int upperBound);

    native void randombytes_buf(byte[] buffer, int size);

    native void randombytes_buf_deterministic(byte[] buffer, int size, byte[] seed);



    //// -------------------------------------------|
    //// PASSWORD HASHING
    //// -------------------------------------------|
    native int crypto_pwhash(byte[] outputHash,
                                 long outputHashLen,
                                 byte[] password,
                                 long passwordLen,
                                 byte[] salt,
                                 long opsLimit,
                                 long memLimit,
                                 int alg);

    native int crypto_pwhash_str(byte[] outputStr,
                                     byte[] password,
                                     long passwordLen,
                                     long opsLimit,
                                     long memLimit);

    native int crypto_pwhash_str_verify(byte[] hash, byte[] password, long passwordLen);

    native int crypto_pwhash_str_needs_rehash(byte[] hash, long opsLimit, long memLimit);




    //// -------------------------------------------|
    //// KEY DERIVATION FUNCTIONS
    //// -------------------------------------------|
    native void crypto_kdf_keygen(byte[] masterKey);

    native int crypto_kdf_derive_from_key(byte[] subkey,
                                          int subkeyLen,
                                          long subkeyId,
                                          byte[] context,
                                          byte[] masterKey);


    //// -------------------------------------------|
    //// KEY EXCHANGE
    //// -------------------------------------------|
    native int crypto_kx_keypair(byte[] publicKey, byte[] secretKey);

    native int crypto_kx_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

    native int crypto_kx_client_session_keys(
            byte[] rx,
            byte[] tx,
            byte[] clientPk,
            byte[] clientSk,
            byte[] serverPk
    );

    native int crypto_kx_server_session_keys(
            byte[] rx,
            byte[] tx,
            byte[] serverPk,
            byte[] serverSk,
            byte[] clientPk
    );





    //// -------------------------------------------|
    //// SECRET BOX
    //// -------------------------------------------|
    native void crypto_secretbox_keygen(byte[] key);


    native int crypto_secretbox_easy(byte[] cipherText,
                                     byte[] message,
                                     long messageLen,
                                     byte[] nonce,
                                     byte[] key);

    native int crypto_secretbox_open_easy(byte[] message,
                                          byte[] cipherText,
                                          long cipherTextLen,
                                          byte[] nonce,
                                          byte[] key);

    native int crypto_secretbox_detached(byte[] cipherText,
                                         byte[] mac,
                                         byte[] message,
                                         long messageLen,
                                         byte[] nonce,
                                         byte[] key);

    native int crypto_secretbox_open_detached(byte[] message,
                                              byte[] cipherText,
                                              byte[] mac,
                                              byte[] cipherTextLen,
                                              byte[] nonce,
                                              byte[] key);



    //// -------------------------------------------|
    //// CRYPTO BOX
    //// -------------------------------------------|

    native int crypto_box_keypair(byte[] publicKey, byte[] secretKey);

    native int crypto_box_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

    native int crypto_scalarmult_base(byte[] publicKey, byte[] secretKey);

    native int crypto_box_easy(
        byte[] cipherText,
        byte[] message,
        long messageLen,
        byte[] nonce,
        byte[] publicKey,
        byte[] secretKey
    );

    native int crypto_box_open_easy(
            byte[] message,
            byte[] cipherText,
            long cipherTextLen,
            byte[] nonce,
            byte[] publicKey,
            byte[] secretKey
    );

    native int crypto_box_detached(byte[] cipherText,
                                   byte[] mac,
                                   byte[] message,
                                   long messageLen,
                                   byte[] nonce,
                                   byte[] publicKey,
                                   byte[] secretKey);

    native int crypto_box_open_detached(byte[] message,
                                        byte[] cipherText,
                                        byte[] mac,
                                        byte[] cipherTextLen,
                                        byte[] nonce,
                                        byte[] publicKey,
                                        byte[] secretKey);

    native int crypto_box_beforenm(byte[] k, byte[] publicKey, byte[] secretKey);


    native int crypto_box_easy_afternm(
        byte[] cipherText,
        byte[] message,
        long messageLen,
        byte[] nonce,
        byte[] key
    );

    native int crypto_box_open_easy_afternm(
            byte[] message, byte[] cipher,
            long cLen, byte[] nonce,
            byte[] key
    );

    native int crypto_box_detached_afternm(
            byte[] cipherText,
            byte[] mac,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );

    native int crypto_box_open_detached_afternm(byte[] message,
                                        byte[] cipherText,
                                        byte[] mac,
                                        long cipherTextLen,
                                        byte[] nonce,
                                        byte[] key);


    native int crypto_box_seal(byte[] cipher, byte[] message, long messageLen, byte[] publicKey);

    native int crypto_box_seal_open(byte[] m,
                                    byte[] cipher,
                                    long cipherLen,
                                    byte[] publicKey,
                                    byte[] secretKey);

    //// -------------------------------------------|
    //// CRYPTO SIGN
    //// -------------------------------------------|

    native int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);

    native int crypto_sign_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

    native int crypto_sign(
            byte[] signedMessage,
            Long signedMessageLen,
            byte[] message,
            long messageLen,
            byte[] secretKey
    );

    native int crypto_sign_open(
            byte[] message,
            Long messageLen,
            byte[] signedMessage,
            long signedMessageLen,
            byte[] publicKey
    );





    //// -------------------------------------------|
    //// SECRET STREAM
    //// -------------------------------------------|

    native void crypto_secretstream_xchacha20poly1305_keygen(byte[] key);

    native int crypto_secretstream_xchacha20poly1305_init_push(
            SecretStream.State state,
            byte[] header,
            byte[] key
    );

    native int crypto_secretstream_xchacha20poly1305_push(
            SecretStream.State state,
            byte[] cipher,
            Long cipherAddr,
            byte[] message,
            long messageLen,
            byte[] additionalData,
            long additionalDataLen,
            byte  tag
    );

    native int crypto_secretstream_xchacha20poly1305_init_pull(
            SecretStream.State state,
            byte[] header,
            byte[] key
    );

    native int crypto_secretstream_xchacha20poly1305_pull(
            SecretStream.State state,
            byte[] message,
            Long messageAddress,
            byte[] tagAddress,
            byte[] cipher,
            long cipherLen,
            byte[] additionalData,
            long additionalDataLen
    );

    native void crypto_secretstream_xchacha20poly1305_rekey(SecretStream.State state);



    //// -------------------------------------------|
    //// CRYPTO AUTH
    //// -------------------------------------------|
    native int crypto_auth(byte[] tag, byte[] in, long inLen, byte[] key);

    native int crypto_auth_verify(byte[] tag, byte[] in, long inLen, byte[] key);

    native void crypto_auth_keygen(byte[] k);




    //// -------------------------------------------|
    //// SHORT HASH
    //// -------------------------------------------|
    native int crypto_shorthash(byte[] out, byte[] in, long inLen, byte[] key);

    native int crypto_shorthash_keygen(byte[] key);

    //native int crypto_shorthash_siphashx24(byte[] out, byte[] in, long inLen, byte[] key);



    //// -------------------------------------------|
    //// GENERIC HASH
    //// -------------------------------------------|

    native void crypto_generichash_keygen(byte[] k);

    native int crypto_generichash(
            byte[] out, int outLen,
            byte[] in, long inLen,
            byte[] key, int keyLen
    );

    native int crypto_generichash_init(GenericHash.State state,
                                       byte[] key,
                                       int keyLength,
                                       int outLen);

    native int crypto_generichash_update(GenericHash.State state,
                                         byte[] in,
                                         long inLen);

    native int crypto_generichash_final(GenericHash.State state, byte[] out, int outLen);




    //// -------------------------------------------|
    //// AEAD
    //// -------------------------------------------|

    native void crypto_aead_chacha20poly1305_keygen(byte[] key);

    native int crypto_aead_chacha20poly1305_encrypt(
            byte[] c,
            long cLen,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_chacha20poly1305_decrypt(
            byte[] m,
            long mLen,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_chacha20poly1305_encrypt_detached(
            byte[] c,
            byte[] mac,
            Long macLenAddress,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_chacha20poly1305_decrypt_detached(
            byte[] m,
            byte[] nsec,
            byte[] c,
            long cLen,
            byte[] mac,
            byte[] ad,
            long adLen,
            byte[] npub,
            byte[] k
    );

    // ietf

    native void crypto_aead_chacha20poly1305_ietf_keygen(byte[] key);

    native int crypto_aead_chacha20poly1305_ietf_encrypt(
            byte[] c,
            long cLen,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_chacha20poly1305_ietf_decrypt(
            byte[] m,
            long mLen,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            byte[] c,
            byte[] mac,
            Long macLenAddress,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            byte[] m,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] mac,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );

    // xchacha

    native void crypto_aead_xchacha20poly1305_ietf_keygen(byte[] k);

    native int crypto_aead_xchacha20poly1305_ietf_encrypt(
            byte[] c,
            long cLen,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_xchacha20poly1305_ietf_decrypt(
            byte[] m,
            long mLen,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );


    native int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            byte[] c,
            byte[] mac,
            Long macLenAddress,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    native int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            byte[] m,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] mac,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );


}
