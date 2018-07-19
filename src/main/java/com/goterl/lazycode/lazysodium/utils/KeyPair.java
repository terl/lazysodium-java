/*
 * Copyright (c) Terl Tech Ltd • 11/05/18 23:35 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.utils;


public class KeyPair {
    private Key secretKey;
    private Key publicKey;

    public KeyPair(Key publicKey, Key secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    public Key getSecretKey() {
        return secretKey;
    }

    public Key getPublicKey() {
        return publicKey;
    }
}
