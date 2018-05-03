/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.sun.jna.Native;

public class Sodium {


    public Sodium() {
        this("sodium");
    }


    public Sodium(String path) {
        Native.register(path);
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


}
