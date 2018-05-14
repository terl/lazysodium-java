/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import java.nio.charset.Charset;

public interface Base {

    // --- Result handling

    boolean boolify(int res);
    <T> T res(int res, T object);



    // --- Conversion handling

    /**
     * Converts a byte array to a string
     * using a charset. Warning
     * this will produce null bytes and unexpected
     * carriage returns. Please use {@link Helpers.Lazy#sodiumBin2Hex(byte[])}
     * to ensure no nulls or carriage breaks.
     * @param bs The byte array.
     * @return The string.
     */
    String str(byte[] bs);


    /**
     * Convert a byte array to a string
     * with a charset. Warning
     * this will produce null bytes and unexpected
     * carriage returns. Please use {@link Helpers.Lazy#sodiumBin2Hex(byte[])}
     * to ensure no nulls or carriage breaks.
     * @param bs Byte array.
     * @param charset The charset.
     * @return The byte array as a string.
     */
    String str(byte[] bs, Charset charset);


    /**
     * Convert a string to bytes.
     * @param s The String to convert to a byte array.
     * @return A byte array from {@code s}.
     */
    byte[] bytes(String s);


    // --- Convenience

    boolean wrongLen(byte[] bs, int shouldBeLen);
    boolean wrongLen(int byteLength, int shouldBeLen);
    boolean wrongLen(int byteLength, long shouldBeLen);
    byte[] removeNulls(byte[] bs);
}
