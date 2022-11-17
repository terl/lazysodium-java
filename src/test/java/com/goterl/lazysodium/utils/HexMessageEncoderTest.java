/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.utils;

import com.goterl.lazysodium.BaseTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HexMessageEncoderTest extends BaseTest {

    @Test
    public void decodeEqualsEncode() {
        HexMessageEncoder encoder = new HexMessageEncoder();

        String cipherText = "612D6865782D656E636F6465642D737472696E67";
        byte[] cipher = encoder.decode(cipherText);

        assertEquals(cipherText, encoder.encode(cipher));
    }
}
