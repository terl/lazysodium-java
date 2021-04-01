/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.utils.Constants;
import com.goterl.lazysodium.utils.Key;

public interface StreamJava extends Stream {

    int SALSA2012_KEYBYTES = 32, SALSA2012_NONCEBYTES = 8,
        SALSA208_KEYBYTES = 32, SALSA208_NONCEBYTES = 8,
        XCHACHA20_KEYBYTES = 32, XCHACHA20_NONCEBYTES = 24;

    long SALSA2012_MESSAGEBYTES_MAX = Constants.SIZE_MAX,
         SALSA208_MESSAGEBYTES_MAX = Constants.SIZE_MAX,
         XCHACHA20_MESSAGEBYTES_MAX = Constants.SIZE_MAX;


    enum Method {
        SALSA20_12,
        SALSA20_8,
        XCHACHA20,
    }


    interface Native extends Stream.Native {

        void cryptoStreamSalsa2012Keygen(byte[] key);

        boolean cryptoStreamSalsa2012(
                byte[] c,
                long cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamSalsa2012Xor(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] key
        );

        void cryptoStreamSalsa208Keygen(byte[] key);

        boolean cryptoStreamSalsa208(
                byte[] c,
                long cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamSalsa208Xor(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] key
        );


        // XChaCha20

        void cryptoStreamXChaCha20Keygen(byte[] key);

        boolean cryptoStreamXChaCha20(
                byte[] c,
                long cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamXChaCha20Xor(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamXChaCha20Ic(
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );


    }



    interface Lazy extends Stream.Lazy {

        Key cryptoStreamKeygen(StreamJava.Method method);

        byte[] cryptoStream(
                byte[] nonce,
                Key key,
                StreamJava.Method method
        );

        String cryptoStreamXor(
                String message,
                byte[] nonce,
                Key key,
                StreamJava.Method method
        );

        String cryptoStreamXorDecrypt(
                String cipher,
                byte[] nonce,
                Key key,
                StreamJava.Method method
        );

        String cryptoStreamXorIc(
                String message,
                byte[] nonce,
                long ic,
                Key key,
                StreamJava.Method method
        );

        String cryptoStreamXorIcDecrypt(
                String cipher,
                byte[] nonce,
                long ic,
                Key key,
                StreamJava.Method method
        );

    }

}
