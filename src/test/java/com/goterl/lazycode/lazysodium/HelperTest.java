/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;import junit.framework.TestCase;
import org.junit.Test;

public class HelperTest extends BaseTest {

    @Test
    public void compare() {
        byte[] b1 = new byte[] { 4, 2, 2, 1 };
        byte[] b2 = new byte[] { 4, 2, 2, 1 };

        int r = lazySodium.getSodium().sodium_compare(b1, b2, 4);

        TestCase.assertEquals(0, r);
    }


}
