/*
 * Copyright (c) Terl Tech Ltd • 15/05/18 15:39 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.LazySodium;


public class Detached {

    byte[] mac;

    public Detached(byte[] mac) {
        this.mac = mac;
    }

    public byte[] getMac() {
        return mac;
    }

    public String getMacString() {
        return LazySodium.toHex(getMac());
    }

}
