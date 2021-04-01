/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertNotEquals;

public class SodiumJavaTest {

    @Test
    // This test is ignored for two reasons:
    //  - We cannot assume that libsodium is installed on any machine
    //  - Loading is a no-op if libsodium has already been loaded by another test (say, from resources)
    // It is supposed to work with 'sodium', 'libsodium.so' (platform dependent) and
    // '/usr/lib/x86_64-linux-gnu/libsodium.so'
    @Ignore
    public void canLoadWithSystemLibrary() {
        SodiumJava sodium = new SodiumJava("sodium");
        int initResult = sodium.sodium_init();
        assertNotEquals(-1, initResult);
    }


}
