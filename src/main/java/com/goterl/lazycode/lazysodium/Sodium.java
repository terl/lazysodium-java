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
import com.goterl.lazycode.lazysodium.utils.NativeUtils;
import com.sun.jna.Native;
import com.sun.jna.Platform;

import java.io.File;
import java.io.IOException;

public class Sodium {


    private Sodium() {
        registerFromResources();
    }

    /**
     * Please note that the libsodium.so
     * file HAS to be built for the platform this program will run on.
     *
     * @param path Absolute path to libsodium.so.
     */
    private Sodium(String path) {
        registerFromPath(path);
    }

    /**
     * If on the Android platform, then this is the intended
     * route to load a libsodium.so. Please note loading for Android is not
     * the same as loading for Java.
     * The path must be to a directory with all the Android ABIs, which each
     * contain the libsodium.so. For example, given {@code /path/to/ABI1/}, {@code /path/to/THE_ABI2/}
     * and {@code /path/to/THE_ABI3/}, the param {@code path} should be {@code /path/to/}.
     * ABI1, ABI2 and ABI3 all contain libsodium.so built for that specific ABI.
     *
     * @param path Absolute path to the parent directory of all the ABI directories.
     * @param isAndroid Set to true if the program will execute in an Android environment.
     */
    private Sodium(String path, boolean isAndroid) {
        // If it's the android platform then we load
        // the libsodium.so files from the "src/main/libs" folder.
        // This folder should have folders with ABI names
        // such as x86 or x86_64 etc.
        if (isAndroid) Native.register(Sodium.class, path);

        // If the path is provided to us, then we
        else registerFromPath(path);
    }

    public static Sodium loadJava() {
        return new Sodium();
    }

    /**
     * Please see {@link Sodium#Sodium(String)}.
     * @param libSodiumNativeLibPath Absolute path to a libsodium.so file.
     * @return Sodium instance.
     */
    public static Sodium loadJava(String libSodiumNativeLibPath) {
        return new Sodium(libSodiumNativeLibPath);
    }

    public static Sodium loadAndroid() {
        return new Sodium("sodium", true);
    }

    /**
     * Please see {@link Sodium#Sodium(String, boolean)}.
     * @param libSodiumNativeLibPath Absolute path to parent directory of all the ABIs.
     * @return Sodium instance.
     */
    public static Sodium loadAndroid(String libSodiumNativeLibPath) {
        return new Sodium(libSodiumNativeLibPath, true);
    }

    private void registerFromResources() {
        String path = getLibSodiumFromResources();
        try {
            NativeUtils.loadLibraryFromJar(path);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * All paths must be absolute.
     */
    private void registerFromPath(String path) {
        Native.register(Sodium.class, path);
    }

    private String getLibSodiumFromResources() {
        String path = getPath("windows", "libsodium.dll");
        if (Platform.isLinux() || Platform.isAndroid()) {
            path = getPath("linux", "libsodium.so");
        } else if (Platform.isMac()) {
            path = getPath("mac", "libsodium.dylib");
        }
        return path;
    }

    private String getPath(String folder, String name) {
        String resourcePath = folder + File.separator + name;
        if (!resourcePath.startsWith(File.separator)) {
            resourcePath = File.separator + resourcePath;
        }
        return resourcePath;
    }



    //// -------------------------------------------|
    //// HELPERS
    //// -------------------------------------------|

    // Cannot implement as these methods request pointers.
    // native int sodium_memcmp(ptr b1, ptr b2, int len);
    // native byte[] sodium_bin2hex(char[] hex, int hexMaxLen, char[] bin, int binLen);

    // TODO: sodium_bin2base64, sodium_base642bin, sodium_increment, sodium_add
    // TODO: sodium_compare, sodium_is_zero, sodium_stackzero


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
    //// SECRET SCREAM
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
            byte tag
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
            byte tagAddress,
            byte[] cipher,
            long cipherLen,
            byte[] additionalData,
            long additionalDataLen
    );



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

    native int crypto_shorthash_siphashx24(byte[] out, byte[] in, long inLen, byte[] key);



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

    native int crypto_aead_chacha20poly1305_keygen(byte[] key);

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
            byte[] nsec,
            byte[] c,
            long cLen,
            byte[] mac,
            byte[] ad,
            long adLen,
            byte[] npub,
            byte[] k
    );

}
