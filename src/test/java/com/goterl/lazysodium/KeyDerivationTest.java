/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.KeyDerivation;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;


public class KeyDerivationTest extends BaseTest {

    static final byte[] LONG_CONTEXT = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8};
    static final byte[] VALID_CONTEXT = new byte[]{0, 1, 2, 3, 4, 5, 6, 7};
    static final byte[] SHORT_CONTEXT = new byte[]{0, 1, 2, 3, 4, 5};
    static final byte[] VALID_KEY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    static final byte[] OUT_VALID_KEY_VALID_CONTEXT_1 = new byte[]{61, -17, -126, -25, -14, 29, 2, -83, 89, -120, 37, -35, 102, -11, -77, -59};
    private KeyDerivation.Native keyDerivation;
    private KeyDerivation.Lazy keyDerivationLazy;

    @BeforeAll
    public void before() {
        keyDerivation = lazySodium;
        keyDerivationLazy = lazySodium;
    }

    @Test
    public void keygen() throws SodiumException {
        byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES];
        String contextStr = "Examples";
        byte[] context = lazySodium.bytes(contextStr);
        // Create a master key
        keyDerivation.cryptoKdfKeygen(masterKey);

        // Create subkey number 1 with the max bytes
        byte[] subKey = new byte[KeyDerivation.BYTES_MAX];
        keyDerivation.cryptoKdfDeriveFromKey(
                subKey, subKey.length, 1L,
                context, masterKey
        );

        String skStr = lazySodium.toHexStr(subKey);

        // Create subkey number 2 exactly the same as
        // subkey number 1.
        Key skStr2 = keyDerivationLazy.cryptoKdfDeriveFromKey(
                KeyDerivation.BYTES_MAX,
                1L,
                contextStr,
                Key.fromBytes(masterKey)
        );

        assertEquals(skStr, skStr2.getAsHexString());
    }

    @Test
    public void doesRawGen() {
        byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES];
        keyDerivation.cryptoKdfKeygen(masterKey);
    }

    @Test
    public void doesRawGenSubEachTime() {
        byte[] out = new byte[KeyDerivation.BYTES_MIN];
        int result = keyDerivation.cryptoKdfDeriveFromKey(out, KeyDerivation.BYTES_MIN, 1L, VALID_CONTEXT, VALID_KEY);
        assertEquals(0, result);
        assertArrayEquals(OUT_VALID_KEY_VALID_CONTEXT_1, out);
    }

    @Test
    public void doesntGenerateShortKeys() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES - 5];
            keyDerivation.cryptoKdfKeygen(masterKey);
        });
    }

    @Test
    public void doesntGenerateLongKeys() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES + 5];
            keyDerivation.cryptoKdfKeygen(masterKey);
        });
    }

    private byte[] generateKeyOfAnyLength(int length) {
        byte[] masterKey = new byte[length];
        // Using default instance for expedience. While some real-world
        // use-cases might need blocking random, the default provider (which
        // is usually non-blocking) is sufficient for tests.
        new SecureRandom().nextBytes(masterKey);
        return masterKey;
    }

    private byte[] makeValidOut() {
        return new byte[KeyDerivation.BYTES_MAX];
    }

    @Test
    public void doesntAllowShortKeys() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] masterKey = generateKeyOfAnyLength(KeyDerivation.MASTER_KEY_BYTES);
            byte[] invalidLengthOut = new byte[2];
            keyDerivation.cryptoKdfDeriveFromKey(invalidLengthOut, invalidLengthOut.length, 1L, VALID_CONTEXT, masterKey);
        });
    }

    @Test
    public void doesntAllowLongKeys() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] masterKey = generateKeyOfAnyLength(KeyDerivation.MASTER_KEY_BYTES);
            byte[] invalidLengthOut = new byte[200];
            keyDerivation.cryptoKdfDeriveFromKey(invalidLengthOut, invalidLengthOut.length, 1L, VALID_CONTEXT, masterKey);
        });
    }

    @Test
    public void doesntAllowShortContext() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] out = makeValidOut();
            keyDerivation.cryptoKdfDeriveFromKey(out, out.length, 1L, SHORT_CONTEXT, VALID_KEY);
        });
    }

    @Test
    public void doesntAllowLongContext() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] out = makeValidOut();
            keyDerivation.cryptoKdfDeriveFromKey(out, out.length, 1L, LONG_CONTEXT, VALID_KEY);
        });
    }

    @Test
    public void doesntAllowShortSubKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] out = new byte[KeyDerivation.BYTES_MIN - 1];
            keyDerivation.cryptoKdfDeriveFromKey(out, out.length, 1L, VALID_CONTEXT, VALID_KEY);
        });
    }

    @Test
    public void doesntAllowLongSubKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] out = new byte[KeyDerivation.BYTES_MAX + 1];
            keyDerivation.cryptoKdfDeriveFromKey(out, out.length, 1L, VALID_CONTEXT, VALID_KEY);
        });
    }

    @Test
    public void doesntAllowSubKeyShorterThanSpecified() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] out = new byte[KeyDerivation.BYTES_MAX - 1];
            keyDerivation.cryptoKdfDeriveFromKey(out, KeyDerivation.BYTES_MAX, 1L, VALID_CONTEXT, VALID_KEY);
        });
    }
}
