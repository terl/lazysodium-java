/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.sun.jna.Native;
import com.sun.jna.Platform;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

public class Sodium {


    public Sodium() {
        String path = getLibSodiumFromResources();
        register(path);
    }


    public Sodium(String path) {
        register(path);
    }

    private void register(String path) {
        Native.register(path);
    }

    private String getLibSodiumFromResources() {
        ClassLoader loader = this.getClass().getClassLoader();
        String path = null;
        try {
            path = getSodiumLib(loader, "windows", "libsodium.dll");
            if (Platform.isLinux()) {
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


}
