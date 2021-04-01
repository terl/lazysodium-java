/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.utils;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.interfaces.MessageEncoder;

public class HexMessageEncoder implements MessageEncoder {

    @Override
    public String encode(byte[] cipher) {
        return LazySodium.toHex(cipher);
    }

    @Override
    public byte[] decode(String cipherText) {
        return LazySodium.toBin(cipherText);
    }
}
