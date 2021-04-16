/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.utils;


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

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof KeyPair)) return false;
        KeyPair other = (KeyPair) obj;
        return other.getSecretKey().equals(getSecretKey())
                && other.getPublicKey().equals(getPublicKey());
    }
}
