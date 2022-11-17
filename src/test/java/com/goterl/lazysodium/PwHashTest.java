/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.PwHash;
import com.goterl.lazysodium.interfaces.Scrypt;
import com.sun.jna.NativeLong;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PwHashTest extends BaseTest {

    private final String PASSWORD = "Password123456!!!!@@";
    private PwHash.Lazy pwHashLazy;

    @BeforeAll
    public void before() {
        pwHashLazy = (PwHash.Lazy) lazySodium;
    }

    @Test
    public void scryptHash() throws SodiumException {
        byte[] salt = new byte[LazySodium.longToInt(Scrypt.SCRYPTSALSA208SHA256_SALT_BYTES)];
        String scryptHash = lazySodium.cryptoPwHashScryptSalsa208Sha256(
                PASSWORD,
                300L, // This can be anything up to Constants.SIZE_MAX
                salt,
                Scrypt.SCRYPTSALSA208SHA256_OPSLIMIT_MIN,
                Scrypt.SCRYPTSALSA208SHA256_MEMLIMIT_MIN
        );

        String hash = lazySodium.cryptoPwHashScryptSalsa208Sha256Str(
                PASSWORD,
                Scrypt.SCRYPTSALSA208SHA256_OPSLIMIT_MIN,
                Scrypt.SCRYPTSALSA208SHA256_MEMLIMIT_MIN
        );

        boolean isCorrect = lazySodium.cryptoPwHashScryptSalsa208Sha256StrVerify(hash, PASSWORD);


        assertTrue(isCorrect, "Minimum hashing failed.");
    }

    @Test
    public void nativeHash() throws SodiumException {
        String output = pwHashLazy.cryptoPwHash(
                PASSWORD,
                PwHash.BYTES_MIN,
                lazySodium.randomBytesBuf(PwHash.SALTBYTES),
                5L,
                new NativeLong(8192 * 2),
                PwHash.Alg.PWHASH_ALG_ARGON2ID13
        );

        assertNotNull("Native hashing failed.", output);
    }

    @Test
    public void strMin() throws SodiumException {
        String hash = pwHashLazy.cryptoPwHashStr(
                PASSWORD,
                3,
                PwHash.MEMLIMIT_MIN
        );

        boolean isCorrect = pwHashLazy.cryptoPwHashStrVerify(hash, PASSWORD);

        assertTrue(isCorrect, "Minimum hashing failed.");
    }


    // We don't test for this as it's pretty demanding and
    // will fail on most machines
    public void cryptoPwHashStrTestSensitive() {}

}
