/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HelperTest extends BaseTest {

    @Test
    public void compare() {
        byte[] b1 = new byte[] { 4, 2, 2, 1 };
        byte[] b2 = new byte[] { 4, 2, 2, 1 };

        int r = lazySodium.getSodium().sodium_compare(b1, b2, 4);

        assertEquals(0, r);
    }
}
