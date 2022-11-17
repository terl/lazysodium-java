/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ShortHashTest extends BaseTest {


    @Test
    public void hash() throws SodiumException {
        String hashThis = "This should get hashed";

        Key key = lazySodium.cryptoShortHashKeygen();
        String hash = lazySodium.cryptoShortHash(hashThis, key);

        assertNotNull(hash);
    }



}
