/*
 * Copyright (c) Terl Tech Ltd • 12/05/18 16:25 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.BaseChecker;
import com.goterl.lazycode.lazysodium.utils.Constants;
import com.goterl.lazycode.lazysodium.utils.KeyPair;

public interface CryptoSign {


    int ED25519_PUBLICKEYBYTES = 32,
        ED25519_BYTES = 64,
        ED25519_SECRETKEYBYTES = 64,
        ED25519_SEEDBYTES = 32;

    long ED25519_MESSAGEBYTES_MAX = Constants.SIZE_MAX - ED25519_BYTES;

    int BYTES = ED25519_BYTES,
        PUBLICKEYBYTES = ED25519_PUBLICKEYBYTES,
        SECRETKEYBYTES = ED25519_SECRETKEYBYTES,
        SEEDBYTES = ED25519_SEEDBYTES;

    long MESSAGEBYTES_MAX = ED25519_MESSAGEBYTES_MAX;



    class Checker extends BaseChecker { }


    interface Native {

       int cryptoSignKeypair(byte[] publicKey, byte[] secretKey);

       int cryptoSignSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);

       int cryptoSign(
                byte[] signedMessage,
                Long signedMessageLen,
                byte[] message,
                long messageLen,
                byte[] secretKey
        );

       int cryptoSignOpen(
                byte[] message,
                Long messageLen,
                byte[] signedMessage,
                long signedMessageLen,
                byte[] publicKey
        );


    }

    interface Lazy {




    }


}
