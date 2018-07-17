/*
 * Copyright (c) Terl Tech Ltd • 17/07/18 21:28 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.Constants;

public interface Stream {

    // REGULAR CHACHA

    int CHACHA20_NONCEBYTES = 8, CHACHA20_KEYBYTES = 32;
    long CHACHA20_MESSAGEBYTES_MAX = Constants.SIZE_MAX;

    // IETF CHACHA

    int CHACHA20_IETF_NONCEBYTES = 12, CHACHA20_IETF_KEYBYTES = 32;
    long CHACHA20_IETF_MESSAGEBYTES_MAX = Constants.GB_256;



    enum Method {
        CHACHA20,
        CHACHA20_IETF,
        XCHACHA20,
        SALSA20,
        XSALSA20,
    }



    interface Native {

        boolean cryptoStreamChaCha20(
                byte[] c,
                long cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChaCha20Xor(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChacha20XorIc(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

        // IETF CHACHA

        boolean cryptoStreamChaCha20Ietf(
                byte[] c,
                long cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChaCha20IetfXor(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChacha20IetfXorIc(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

    }



    interface Lazy {



    }

}
