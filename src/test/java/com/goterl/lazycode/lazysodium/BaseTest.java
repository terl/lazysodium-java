/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.utils.LibraryLoader;
import org.junit.Before;

public class BaseTest {

    public static LazySodiumJava lazySodium;

    @Before
    public void doBeforeEverything() {
        lazySodium = new LazySodiumJava(new SodiumJava(LibraryLoader.Mode.BUNDLED_ONLY));
    }

}
