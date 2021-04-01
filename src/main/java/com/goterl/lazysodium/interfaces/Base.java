/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import java.nio.charset.Charset;

public interface Base {

    // --- Result handling

    boolean successful(int res);
    <T> T res(int res, T object);



    // --- Conversion handling

    /**
     * Converts a byte array to a string
     * using a charset. This may not be what you want to use if you're storing this string
     * in a database for example. This function will produce null bytes and unexpected
     * carriage returns. Please use {@link Helpers.Lazy#sodiumBin2Hex(byte[])}
     * to convert your byte array to a hexadecimal string that ensures no nulls or carriage breaks.
     * @param bs The byte array.
     * @return The string.
     */
    String str(byte[] bs);


    /**
     * Convert a byte array to a string with a charset.
     * This may not be what you want to use if you're storing this string
     * in a database for example. This function will produce null bytes and unexpected
     * carriage returns. Please use {@link Helpers.Lazy#sodiumBin2Hex(byte[])}
     * to convert your byte array to a hexadecimal string that ensures no nulls or carriage breaks.
     * @param bs Byte array.
     * @param charset The charset.
     * @return The byte array as a string.
     */
    String str(byte[] bs, Charset charset);


    /**
     * Convert a string to directly bytes.
     * @param s The String to convert to a byte array.
     * @return A byte array from {@code s}.
     */
    byte[] bytes(String s);


    // --- Convenience

    boolean wrongLen(byte[] bs, int shouldBeLen);
    boolean wrongLen(int byteLength, int shouldBeLen);
    boolean wrongLen(int byteLength, long shouldBeLen);

    /**
     * Remove all the null bytes from the
     * end of a byte array.
     * @param bs A byte array.
     * @return The byte array with no null bytes at the end.
     */
    byte[] removeNulls(byte[] bs);
}
