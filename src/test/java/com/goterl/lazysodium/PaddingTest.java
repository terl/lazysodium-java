/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PaddingTest extends BaseTest {


    @Test
    public void paddingTest1() {
        int maxBufLen = 10;
        int blockSize = 4;
        int expectedPadLength = 8;
        String padThis = "test";
        pad(padThis, blockSize, maxBufLen, expectedPadLength);
    }

    @Test
    public void paddingTest2() {
        int maxBufLen = 50;
        int blockSize = 49;
        int expectedPadLength = 49;
        String padThis = "hi";
        pad(padThis, blockSize, maxBufLen, expectedPadLength);
    }

    @Test
    public void paddingTest3() {
        int maxBufLen = 20;
        int blockSize = 3;
        int expectedPadLength = 9;
        String padThis = "zebras";
        pad(padThis, blockSize, maxBufLen, expectedPadLength);
    }

    private void pad(String padThis, int blockSize, int maxBufLen, int expectedPadLength) {
        // This asks the C side to store the final padded size
        // inside this JNA object.
        IntByReference finalPaddedLength = new IntByReference();
        int contentsLength = padThis.length();

        // Create some native memory that is of the maximum
        // size and then set the string into it.
        Pointer p = new Memory(maxBufLen);
        p.setString(0, padThis);

        // Pad
        lazySodium.getSodium().sodium_pad(finalPaddedLength, p, contentsLength, blockSize, maxBufLen);

        // Test
        assertEquals(expectedPadLength, finalPaddedLength.getValue());

        // Test unpadding of this padded string
        int finalLength = finalPaddedLength.getValue();

        // Uncomment to print the string at this point
        //printString(p, finalLength);

        unPad(padThis, p, finalLength, blockSize, contentsLength);
    }

    public void unPad(String startingString, Pointer paddedPointer, int lengthOfArray, int blockSize, int expectedUnpaddedLength) {
        IntByReference unpadRef = new IntByReference();
        lazySodium.getSodium().sodium_unpad(unpadRef, paddedPointer, lengthOfArray, blockSize);
        assertEquals(expectedUnpaddedLength, unpadRef.getValue());

        String finishingString = pointerToString(paddedPointer, unpadRef.getValue());
        assertEquals(startingString, finishingString);
    }

    private String pointerToString(Pointer p, int length) {
        return new String(p.getByteArray(0, length));
    }

    private void printString(Pointer p, int length) {
        System.out.println(pointerToString(p, length));
    }
}
