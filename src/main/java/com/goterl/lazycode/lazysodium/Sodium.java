/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.structs.crypto_secretstream_xchacha20poly1305_state;
import com.sun.jna.Native;
import com.sun.jna.Platform;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

public class Sodium {


    private Sodium() {
        String path = getLibSodiumFromResources();
        register(path);
    }

    private Sodium(String path) {
        register(path);
    }

    private Sodium(String path, boolean isAndroid) {
        if (isAndroid) Native.register(Sodium.class, path);
        else register(path);
    }

    public static Sodium loadJava() {
        return new Sodium();
    }

    public static Sodium loadJava(String path) {
        return new Sodium(path);
    }

    public static Sodium loadAndroid() {
        return new Sodium("sodium", true);
    }

    public static Sodium loadAndroid(String libsodiumPath) {
        return new Sodium(libsodiumPath, true);
    }

    private void register(String path) {
        Native.register(path);
    }

    private String getLibSodiumFromResources() {
        ClassLoader loader = this.getClass().getClassLoader();
        String path = null;
        try {
            path = getSodiumLib(loader, "windows", "libsodium.dll");
            if (Platform.isLinux() || Platform.isAndroid()) {
                path = getSodiumLib(loader, "linux", "libsodium.so");
            } else if (Platform.isMac()) {
                path = getSodiumLib(loader, "mac", "libsodium.dylib");
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        return path;
    }

    private String getSodiumLib(ClassLoader loader, String folder, String name) throws URISyntaxException {
        URL url = loader.getResource(folder);
        return new File(url.toURI()).toPath().resolve(name).toString();
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

    native byte randombytes_uniform(byte upperBound);

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
                                          byte[] cipherTextLen,
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
            crypto_secretstream_xchacha20poly1305_state state,
            byte[] header,
            byte[] key
    );

    native int crypto_secretstream_xchacha20poly1305_push(
            crypto_secretstream_xchacha20poly1305_state state,
            byte[] cipher,
            Long cipherAddr,
            byte[] message,
            long messageLen,
            byte[] additionalData,
            long additionalDataLen,
            byte tag
    );

    native int crypto_secretstream_xchacha20poly1305_init_pull(
            crypto_secretstream_xchacha20poly1305_state state,
            byte[] header,
            byte[] key
    );

    native int crypto_secretstream_xchacha20poly1305_pull(
            crypto_secretstream_xchacha20poly1305_state state,
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
}
