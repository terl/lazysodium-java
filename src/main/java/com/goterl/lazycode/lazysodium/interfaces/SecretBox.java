/*
 * Copyright (c) Terl Tech Ltd • 03/05/18 11:27 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.BaseChecker;

public interface SecretBox {


    int XSALSA20POLY1305_KEYBYTES = 32,
        XSALSA20POLY1305_NONCEBYTES = 24,
        XSALSA20POLY1305_MACBYTES = 16;

    int KEYBYTES = XSALSA20POLY1305_KEYBYTES,
        MACBYTES = XSALSA20POLY1305_MACBYTES,
        NONCEBYTES = XSALSA20POLY1305_NONCEBYTES;


    class Checker extends BaseChecker {

        public static boolean checkKeyLen(int len) {
            return KEYBYTES == len;
        }

        public static boolean checkMacLen(int len) {
            return MACBYTES == len;
        }

        public static boolean checkNonceLen(int len) {
            return NONCEBYTES == len;
        }

    }

    interface Native {
        void cryptoSecretBoxKeygen(byte[] key);
        boolean cryptoSecretBoxEasy(byte[] cipherText,
                                 byte[] message,
                                 long messageLen,
                                 byte[] nonce,
                                 byte[] key);

        boolean cryptoSecretBoxOpenEasy(byte[] message,
                                      byte[] cipherText,
                                      byte[] cipherTextLen,
                                      byte[] nonce,
                                      byte[] key);

        boolean cryptoSecretBoxDetached(byte[] cipherText,
                                     byte[] mac,
                                     byte[] message,
                                     long messageLen,
                                     byte[] nonce,
                                     byte[] key);

        boolean cryptoSecretBoxOpenDetached(byte[] message,
                                          byte[] cipherText,
                                          byte[] mac,
                                          byte[] cipherTextLen,
                                          byte[] nonce,
                                          byte[] key);
    }

    interface Lazy {

    }


}
