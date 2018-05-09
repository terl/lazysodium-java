/*
 * Copyright (c) Terl Tech Ltd • 09/05/18 01:25 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


public interface KeyExchange {

    int PUBLICKEYBYTES = 32;
    int SECRETKEYBYTES = 32;
    int SESSIONKEYBYTES = 32;
    int SEEDBYTES = 32;
    String PRIMITIVE = "x25519blake2b";


    interface Native {
        int cryptoKxKeypair(byte[] publicKey, byte[] secretKey);
        int cryptoKxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);
        int cryptoKxClientSessionKeys(
                byte[] rx,
                byte[] tx,
                byte[] clientPk,
                byte[] clientSk,
                byte[] serverPk
        );
        int cryptoKxServerSessionKeys(
                byte[] rx,
                byte[] tx,
                byte[] serverPk,
                byte[] serverSk,
                byte[] clientPk
        );
    }

    interface Lazy {

    }


}
