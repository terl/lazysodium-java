/*
 * Copyright (c) Terl Tech Ltd • 11/05/18 23:26 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.Sodium;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.BaseChecker;

import java.nio.charset.Charset;

public interface CryptoBox {


    int CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32,
        CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32,
        CURVE25519XSALSA20POLY1305_MACBYTES = 16,
        CURVE25519XSALSA20POLY1305_SEEDBYTES = 32,
        CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32;

    int PUBLICKEYBYTES = 32,
        SECRETKEYBYTES = 32,
        MACBYTES = 16,
        SEEDBYTES = 32,
        BEFORENMBYTES = 32;




    class Checker extends BaseChecker {

        public static boolean checkPublicKey(int len) {
            return PUBLICKEYBYTES == len;
        }

        public static boolean checkMac(int len) {
            return MACBYTES == len;
        }

        public static boolean checkSecretKey(int len) {
            return SECRETKEYBYTES == len;
        }

        public static boolean checkSeed(int len) {
            return SEEDBYTES == len;
        }

        public static boolean checkBeforeNmBytes(int len) {
            return BEFORENMBYTES == len;
        }

    }




    interface Native {



    }

    interface Lazy {



    }


}
