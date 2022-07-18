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
import junit.framework.TestCase;
import org.junit.Test;

public class SecureMemoryTest extends BaseTest {
    @Test
    public void memZero() {
        byte[] b = new byte[] { 4, 2, 2, 1 };
        boolean res = lazySodium.sodiumMemZero(b, b.length);
        TestCase.assertTrue(isZero(b));
    }

    @Test
    public void memZeroPtr() {
        Pointer p = new Memory(32);
        p.write(0, lazySodium.randomBytesBuf(32), 0, 32);
        TestCase.assertFalse(isZero(p.getByteArray(0, 32)));

        boolean res = lazySodium.sodiumMemZero(p, 32);

        TestCase.assertTrue(res);
        TestCase.assertTrue(isZero(p.getByteArray(0, 32)));

    }

    @Test
    public void mLock() {
        byte[] b = new byte[] { 4, 5, 2, 1 };

        boolean res = lazySodium.sodiumMLock(b, b.length);
        boolean res2 = lazySodium.sodiumMUnlock(b, b.length);

        TestCase.assertTrue(res);
        TestCase.assertTrue(res2);
        TestCase.assertTrue(isZero(b));
    }

    @Test
    public void mLockPtr() {
        Pointer p = new Memory(32);
        p.write(0, lazySodium.randomBytesBuf(32), 0, 32);
        TestCase.assertFalse(isZero(p.getByteArray(0, 32)));

        boolean res = lazySodium.sodiumMLock(p, 32);
        boolean res2 = lazySodium.sodiumMUnlock(p, 32);

        TestCase.assertTrue(res);
        TestCase.assertTrue(res2);
        TestCase.assertTrue(isZero(p.getByteArray(0, 32)));
    }

    @Test
    public void malloc() {
        int size = 10;

        Pointer ptr = lazySodium.sodiumMalloc(size);

        byte[] arr = ptr.getByteArray(0, size);

        TestCase.assertEquals(arr.length, size);

        lazySodium.sodiumFree(ptr);
    }

    @Test
    public void allocArray() {
        int size = 10;

        Pointer ptr = lazySodium.sodiumAllocArray(size, 2);

        byte[] arr = ptr.getByteArray(0, size * 2);

        TestCase.assertEquals(arr.length, size * 2);

        lazySodium.sodiumFree(ptr);
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
