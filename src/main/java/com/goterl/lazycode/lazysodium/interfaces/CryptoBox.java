/*
 * Copyright (c) Terl Tech Ltd • 03/05/18 11:27 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.BaseChecker;

public interface CryptoBox {


    int
            CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SEEDBYTES = 32,

            CRYPTO_BOX_SEEDBYTES = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SEEDBYTES;


    class Checker extends BaseChecker {

    }

    interface Native {

    }

    interface Lazy {

    }


    enum Alg {

    }


}
