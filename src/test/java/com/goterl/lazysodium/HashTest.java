/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Hash;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class HashTest extends BaseTest {


    private String M1 = "With great power ";
    private String M2 = "comes great responsibility";
    private String MESSAGE = M1 + M2;

    @Test
    public void sha256Compare() throws SodiumException {
        String hashed1 = lazySodium.cryptoHashSha256(MESSAGE);
        String hashed2 = lazySodium.cryptoHashSha256(MESSAGE);
        assertNotSame(hashed1, hashed2);
    }

    @Test
    public void sha512Compare() throws SodiumException {
        String hash1 = lazySodium.cryptoHashSha512(MESSAGE);
        String hash2 = lazySodium.cryptoHashSha512(MESSAGE);
        assertNotSame(hash1, hash2);
    }

    @Test
    public void sha512IsLonger() throws SodiumException {
        String hash1 = lazySodium.cryptoHashSha256(MESSAGE);
        String hash2 = lazySodium.cryptoHashSha512(MESSAGE);
        assertTrue(hash1.length() < hash2.length());
    }

    @Test
    public void multipartSha256() throws SodiumException {
        Hash.State256 state = new Hash.State256.ByReference();
        lazySodium.cryptoHashSha256Init(state);

        lazySodium.cryptoHashSha256Update(state, M1);
        lazySodium.cryptoHashSha256Update(state, M2);
        lazySodium.cryptoHashSha256Update(state, "more text to be hashed");

        String hash = lazySodium.cryptoHashSha256Final(state);
        assertNotNull(hash);
    }

    @Test
    public void multipartSha512() throws SodiumException {
        Hash.State512 state = new Hash.State512.ByReference();
        lazySodium.cryptoHashSha512Init(state);

        lazySodium.cryptoHashSha512Update(state, M1);
        lazySodium.cryptoHashSha512Update(state, M2);
        lazySodium.cryptoHashSha512Update(state, "more text to be hashed");

        String hash = lazySodium.cryptoHashSha512Final(state);

        assertNotNull(hash);
    }
}
