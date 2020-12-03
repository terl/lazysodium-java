/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.utils;

import com.sun.jna.NativeLong;

public class BaseChecker {

    public static void checkBetween(String name, long num, long min, long max) {
        if (num < min) {
            throw new IllegalArgumentException("Provided " + name + " is below minimum bound.");
        }
        if (num > max) {
            throw new IllegalArgumentException("Provided " + name + " is above maximum bound.");
        }
    }

    public static void checkBetween(String name, NativeLong num, NativeLong min, NativeLong max) {
        checkBetween(name, num.longValue(), min.longValue(), max.longValue());
    }

    public static boolean isBetween(long num, long min, long max) {
        return min <= num && num <= max;
    }

    public static boolean correctLen(long num, long len) {
        return num == len;
    }

    /**
     * Throw if provided value does not match an expected value.
     */
    public static void checkEqual(String name, int expected, int actual) {
        if (actual != expected) {
            // Neither value is reported, in case this is passed sensitive
            // values, even though most uses are likely for header lengths and
            // similar.
            throw new IllegalArgumentException(
                "Provided " + name + " did not match expected value");
        }
    }

    public static void checkArrayLength(String name, char[] array, long length) {
        checkArrayLength(name, array.length, length);
    }

    public static void checkArrayLength(String name, byte[] array, long length) {
        checkArrayLength(name, array.length, length);
    }

    private static void checkArrayLength(String name, int arrayLength, long length) {
        if (length > arrayLength) {
            throw new IllegalArgumentException("Provided " + name + " array length is larger than array");
        }
        if (length < 0) {
            throw new IllegalArgumentException("Provided " + name + " array length is negative");
        }
    }

}
