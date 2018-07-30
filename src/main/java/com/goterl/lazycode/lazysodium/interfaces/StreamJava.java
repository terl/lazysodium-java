/*
 * Copyright (c) Terl Tech Ltd • 31/07/18 00:22 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


public interface StreamJava extends Stream {


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


    }



    interface Lazy extends Stream.Lazy {



    }

}
