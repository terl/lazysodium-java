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

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Base64MessageEncoderTest extends BaseTest {

    @Test
    public void decodeEqualsEncode() {
        Base64MessageEncoder encoder = new Base64MessageEncoder();
        String expected = "This is a hello from lazysodium";
        String cipherText = "VGhpcyBpcyBhIGhlbGxvIGZyb20gbGF6eXNvZGl1bQ==";
        byte[] plainText = encoder.decode(cipherText);
        String plain = new String(plainText, StandardCharsets.UTF_8);
        assertEquals(expected, plain);
        assertEquals(cipherText, encoder.encode(expected.getBytes(StandardCharsets.UTF_8)));
    }
}
