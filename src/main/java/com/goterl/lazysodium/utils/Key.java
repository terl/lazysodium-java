/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.utils;

import com.goterl.lazysodium.LazySodium;

import java.nio.charset.Charset;
import java.util.Base64;

public class Key {
    private byte[] key;

    private Key(byte[] key) {
        this.key = key;
    }

    public byte[] getAsBytes() {
        return key;
    }

    public String getAsHexString() {
        return LazySodium.toHex(key);
    }

    public String getAsPlainString(Charset charset) {
        return new String(key, charset);
    }

    public String getAsPlainString() {
        return getAsPlainString(Charset.forName("UTF-8"));
    }


    /**
     * Create a Key from a hexadecimal string.
     * @param hexString A hexadecimal encoded string.
     * @return A new Key.
     */
    public static Key fromHexString(String hexString) {
        return new Key(LazySodium.toBin(hexString));
    }

    /**
     * Create a Key from a base64 string.
     * @param base64String A base64 encoded string.
     * @return A new Key.
     */
    public static Key fromBase64String(String base64String) {
        return new Key(Base64.getDecoder().decode(base64String));
    }

    /**
     * Create a Key from a regular, unmodified, not encoded string.
     * @param str A plain string.
     * @return A new Key.
     */
    public static Key fromPlainString(String str) {
        return new Key(str.getBytes(Charset.forName("UTF-8")));
    }

    /**
     * Create a Key from a regular, unmodified, not encoded string.
     * @param str A plain string.
     * @param charset The charset to use.
     * @return A new Key.
     */
    public static Key fromPlainString(String str, Charset charset) {
        return new Key(str.getBytes(charset));
    }

    /**
     * Create a Key by supplying raw bytes. The byte
     * array should not be encoded and should be from a plain string,
     * UNLESS you know what you are doing and actively want
     * to provide a byte array that has been encoded.
     * @param bytes A byte array.
     * @return A new Key.
     */
    public static Key fromBytes(byte[] bytes) {
        return new Key(bytes);
    }

    /**
     * Generate a random Key with a given size.
     * @param ls LazySodium instance as we need to get true
     *           random bytes.
     * @param size The size of the key to generate.
     * @return A new Key.
     */
    public static Key generate(LazySodium ls, int size) {
        return new Key(ls.randomBytesBuf(size));
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Key)) return false;
        Key other = (Key) obj;
        return other.getAsHexString().equalsIgnoreCase(getAsHexString());
    }
}
