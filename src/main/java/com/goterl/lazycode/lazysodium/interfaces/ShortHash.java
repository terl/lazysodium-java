/*
 * Copyright (c) Terl Tech Ltd • 08/05/18 23:48 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.BaseChecker;

public interface ShortHash {

    int SIPHASH24_BYTES = 8,
        SIPHASH24_KEYBYTES = 16,

        BYTES = SIPHASH24_BYTES,
        KEYBYTES = SIPHASH24_KEYBYTES;

    class Checker extends BaseChecker {

    }

    interface Native {
        int cryptoShortHash(byte[] out, byte[] in, long inLen, byte[] key);
        void cryptoShortHashKeygen(byte[] k);
    }

    interface Lazy {

    }


}
