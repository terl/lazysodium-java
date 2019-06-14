/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:52 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;import com.sun.jna.Pointer;
import junit.framework.TestCase;
import org.junit.Test;

public class SecureMemoryAndroidTest extends BaseTest {


    @Test
    public void memZero() {
        byte[] b = new byte[] { 4, 2, 2, 1 };
        boolean res = lazySodium.sodiumMemZero(b, b.length);
        TestCase.assertTrue(isZero(b));
    }

    @Test
    public void mLock() {
        byte[] b = new byte[] { 4, 5, 2, 1 };
        boolean res = lazySodium.sodiumMLock(b, b.length);
        boolean res2 = lazySodium.sodiumMUnlock(b, b.length);
        TestCase.assertTrue(isZero(b));
    }

    @Test
    public void malloc() {
        int size = 10;

        Pointer ptr = lazySodium.sodiumMalloc(size);

        byte[] arr = ptr.getByteArray(0, size);

        TestCase.assertEquals(arr.length, size);
    }

    @Test
    public void free() {
        int size = 10;
        Pointer ptr = lazySodium.sodiumMalloc(size);
        lazySodium.sodiumFree(ptr);
        // If this test reached this comment it didn't segfault
        // so it passes
        TestCase.assertTrue(true);
    }



    private boolean isZero(byte[] arr) {
        boolean allZeroes = true;
        for (byte b : arr) {
            if (b != 0) {
                allZeroes = false;
            }
        }
        return allZeroes;
    }


}
