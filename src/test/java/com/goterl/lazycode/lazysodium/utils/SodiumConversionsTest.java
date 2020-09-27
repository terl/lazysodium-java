package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.SodiumJava;
import com.sun.jna.ptr.IntByReference;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertArrayEquals;

/**
 * Copyright (c) Terl Tech Ltd • 27/09/2020• goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Created by Ugljesa Jovanovic
 * ugljesa.jovanovic@ionspin.com
 * on 27-Sep-2020
 */
public class SodiumConversionsTest {

    public static SodiumJava sodium;

    @Before
    public void doBefore() {
        sodium = new SodiumJava(LibraryLoader.Mode.BUNDLED_ONLY);
    }
    @Test
    public void base64Conversion() {
        IntByReference binLenReference = new IntByReference(0);
        byte[] bin = {1, 2, 3, 4, 5, 32, 64, -128, -1, -128};
        // Encode to base64
        // From libsodium utils.h #define sodium_base64_VARIANT_URLSAFE_NO_PADDING  7
        int maxLen = sodium.sodium_base64_encoded_len(10, 7);
        byte[] base64 = new byte[maxLen];
        sodium.sodium_bin2base64(base64, maxLen, bin, bin.length, 7);
        //Drop the last char which is C \0 terminator character
        String base64String = new String(Arrays.copyOfRange(base64, 0, base64.length - 1));
        assertEquals("AQIDBAUgQID_gA", base64String);
        // Decode from base64
        int reconstructedMaxLen = (base64String.length() * 3) / 4;
        byte[] reconstructedBin = new byte[reconstructedMaxLen];
        sodium.sodium_base642bin(
                reconstructedBin,
                reconstructedMaxLen,
                base64,
                base64.length,
                null,
                binLenReference.getPointer(),
                null,
                7
        );
        assertArrayEquals(bin, reconstructedBin);
        assertEquals(10, binLenReference.getValue());


    }

    @Test
    public void hesConversion() {
        IntByReference binLenReference = new IntByReference(0);
        byte[] bin = {1, 2, 3, 4, 5, 32, 64, -128, -1, -128};
        int hexLen = (bin.length * 2) + 1; // +1 for terminator char
        byte[] hex = new byte[hexLen];
        sodium.sodium_bin2hex(
                hex,
                hexLen,
                bin,
                bin.length
        );
        //Drop the last char which is C \0 terminator character
        String hexString = new String(Arrays.copyOfRange(hex, 0, hex.length - 1));
        assertEquals("0102030405204080ff80", hexString);
        int reconstructedBinSize = (hex.length + 1) / 2;
        byte[] reconstructedBin = new byte[reconstructedBinSize];
        sodium.sodium_hex2bin(
                reconstructedBin,
                reconstructedBinSize,
                hex,
                hex.length,
                null,
                binLenReference.getPointer(),
                null
        );
        byte[] trimmedReconstructedBin = Arrays.copyOfRange(reconstructedBin, 0, binLenReference.getValue());

        assertArrayEquals(bin, trimmedReconstructedBin);
        assertEquals(10, binLenReference.getValue());
    }
}
