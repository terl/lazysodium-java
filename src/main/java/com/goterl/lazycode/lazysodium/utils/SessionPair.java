/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.LazySodium;

public class SessionPair {
    private byte[] rx;
    private byte[] tx;

    public SessionPair(byte[] rx, byte[] tx) {
        this.rx = rx;
        this.tx = tx;
    }

    public SessionPair(String rx, String tx) {
        this.rx = LazySodium.toBin(rx);
        this.tx =  LazySodium.toBin(tx);
    }

    public byte[] getRx() {
        return rx;
    }

    public byte[] getTx() {
        return tx;
    }

    public String getRxString() {
        return LazySodium.toHex(rx);
    }

    public String getTxString() {
        return LazySodium.toHex(tx);
    }
}
