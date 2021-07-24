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
import junit.framework.TestCase;
import org.junit.Test;

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

    private void pad(String padThis, int blockSize, int maxBufLen, int expectedPadLength) {
        IntByReference finalPaddedLength = new IntByReference();
        int contentsLength = padThis.length();
        Pointer p = new Memory(maxBufLen);
        p.setString(0, padThis);

        lazySodium.getSodium().sodium_pad(finalPaddedLength, p, contentsLength, blockSize, maxBufLen);
        TestCase.assertEquals(expectedPadLength, finalPaddedLength.getValue());

        int finalLength = finalPaddedLength.getValue();
        printString(p, finalLength);
        unPad(p, finalLength, blockSize, contentsLength);
    }

    public void unPad(Pointer paddedPointer, int lengthOfArray, int blockSize, int expectedUnpaddedLength) {
        IntByReference unpadRef = new IntByReference();
        lazySodium.getSodium().sodium_unpad(unpadRef, paddedPointer, lengthOfArray, blockSize);
        TestCase.assertEquals(expectedUnpaddedLength, unpadRef.getValue());
        printString(paddedPointer, unpadRef.getValue());
    }

    private void printString(Pointer p, int length) {
        String paddedString = new String(p.getByteArray(0, length));
        System.out.println(paddedString);
    }
}
