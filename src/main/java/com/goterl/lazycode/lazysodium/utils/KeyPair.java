/*
 * Copyright (c) Terl Tech Ltd • 11/05/18 23:35 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.LazySodium;

public class KeyPair {
    private byte[] secretKey;
    private byte[] publicKey;

    public KeyPair(byte[] publicKey, byte[] secretKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    public KeyPair(String publicKey, String secretKey) {
        this.secretKey = LazySodium.toBin(secretKey);
        this.publicKey = LazySodium.toBin(publicKey);
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public String getSecretKeyString() {
        return LazySodium.toHex(secretKey);
    }

    public String getPublicKeyString() {
        return LazySodium.toHex(publicKey);
    }
}
