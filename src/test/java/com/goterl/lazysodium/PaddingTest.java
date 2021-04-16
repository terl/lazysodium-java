/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;
import com.sun.jna.ptr.IntByReference;
import junit.framework.TestCase;
import org.junit.Test;

public class PaddingTest extends BaseTest {


    @Test
    public void pad() {
        IntByReference ref = new IntByReference(0);
        char[] b = new char[4];

        lazySodium.sodiumPad(ref, b, 4, 4, 10);
        TestCase.assertEquals(8, ref.getValue());
    }

}
