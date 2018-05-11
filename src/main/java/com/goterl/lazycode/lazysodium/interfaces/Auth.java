/*
 * Copyright (c) Terl Tech Ltd • 08/05/18 22:59 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.BaseChecker;

public interface Auth {

    int HMACSHA512256_BYTES = 32,
        HMACSHA512256_KEYBYTES = 32,

        BYTES = HMACSHA512256_BYTES,
        KEYBYTES = HMACSHA512256_KEYBYTES;


    class Checker extends BaseChecker {

    }

    interface Native {
        int cryptoAuth(byte[] tag, byte[] in, long inLen, byte[] key);
        int cryptoAuthVerify(byte[] tag, byte[] in, long inLen, byte[] key);
        void cryptoAuthKeygen(byte[] k);
    }

    interface Lazy {

    }


}
