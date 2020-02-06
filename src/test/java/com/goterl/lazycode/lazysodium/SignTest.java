/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.Hash;
import com.goterl.lazycode.lazysodium.interfaces.Sign;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import com.sun.jna.ptr.IntByReference;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;

import static junit.framework.TestCase.*;
import static org.junit.Assert.assertNotNull;


public class SignTest extends BaseTest {


    private Sign.Lazy cryptoSignLazy;

    @Before
    public void before() {
        cryptoSignLazy = (Sign.Lazy) lazySodium;
    }


    @Test
    public void generateKeyPair() throws SodiumException {
        KeyPair keys = cryptoSignLazy.cryptoSignKeypair();
        assertNotNull(keys);
    }

    @Test
    public void generateDeterministicPublicKeyPair() throws SodiumException {
        byte[] seed = new byte[Sign.SEEDBYTES];
        KeyPair keys = cryptoSignLazy.cryptoSignSeedKeypair(seed);
        KeyPair keys2 = cryptoSignLazy.cryptoSignSeedKeypair(seed);

        assertEquals(keys, keys2);
    }

    @Test
    public void generateDeterministicSecretKeyPair() throws SodiumException {
        byte[] seed = new byte[Sign.SEEDBYTES];
        KeyPair keys = cryptoSignLazy.cryptoSignSeedKeypair(seed);
        KeyPair keys2 = cryptoSignLazy.cryptoSignSeedKeypair(seed);

        assertEquals(keys, keys2);
    }


    @Test
    public void signMessage() throws SodiumException {
        String message = "This should get signed";

        KeyPair keyPair = cryptoSignLazy.cryptoSignKeypair();
        String signed = cryptoSignLazy.cryptoSign(message, keyPair.getSecretKey());

        // Now we can verify the signed message.
        String resultingMessage = cryptoSignLazy.cryptoSignOpen(signed, keyPair.getPublicKey());

        TestCase.assertNotNull(resultingMessage);
    }


    @Test
    public void signDetached() throws SodiumException {
        String message = "sign this please";
        KeyPair keyPair = lazySodium.cryptoSignKeypair();

        String signature = lazySodium.cryptoSignDetached(message, keyPair.getSecretKey());
        boolean result = lazySodium.cryptoSignVerifyDetached(signature, message, keyPair.getPublicKey());

        assertTrue(result);
    }

    @Test
    public void convertEd25519ToCurve25519() throws SodiumException {
        Key key1 = Key.fromHexString("0ae5c84877c9c534ffbb1f854550895a25a9ded6bd6b8a9035f38b9e03a0dfe2");
        Key key2 = Key.fromHexString("0ae5c84877c9c534ffbb1f854550895a25a9ded6bd6b8a9035f38b9e03a0dfe2");
        KeyPair ed25519KeyPair = new KeyPair(key1, key2);

        KeyPair curve25519KeyPair = lazySodium.convertKeyPairEd25519ToCurve25519(ed25519KeyPair);

        assertEquals(
                "4c261ac83d4ffec2fd3f3d3e7082c5c18e2d5e144dae343069f48207edcdc43a",
                curve25519KeyPair.getPublicKey().getAsHexString().toLowerCase()
        );
        assertEquals(
                "588c6bcb80ebcbca68c0d039faeac79c0d0abc3f6078f23900760035ff9d0459",
                curve25519KeyPair.getSecretKey().getAsHexString().toLowerCase()
        );
    }

    @Test
    public void cryptoSignEd25519SkToSeed() throws SodiumException {
        byte[] seed = lazySodium.randomBytesBuf(Sign.ED25519_SEEDBYTES);
        KeyPair ed5519KeyPair = lazySodium.cryptoSignSeedKeypair(seed);
        byte[] result = new byte[Sign.ED25519_SEEDBYTES];
        lazySodium.cryptoSignEd25519SkToSeed(result, ed5519KeyPair.getSecretKey().getAsBytes());
        assertEquals(LazySodium.toHex(seed), LazySodium.toHex(result));
    }

    @Test
    public void cryptoSignSecretKeyPair() throws SodiumException {
        KeyPair keys = lazySodium.cryptoSignKeypair();
        KeyPair extracted = lazySodium.cryptoSignSecretKeyPair(keys.getSecretKey());
        assertEquals(keys.getSecretKey().getAsHexString(), extracted.getSecretKey().getAsHexString());
        assertEquals(keys.getPublicKey().getAsHexString(), extracted.getPublicKey().getAsHexString());
    }


    @Test
    public void signLongMessage() throws SodiumException {
        String message = "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed" +
                "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed" +
                "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed" +
                "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed";
        byte[] messageBytes = message.getBytes();

        KeyPair keyPair = cryptoSignLazy.cryptoSignKeypair();
        Key sk = keyPair.getSecretKey();
        Key pk = keyPair.getPublicKey();

        Sign.StateCryptoSign state = new Sign.StateCryptoSign();

        boolean started = lazySodium.cryptoSignInit(state);
        assertTrue("cryptoSignInit not started successfully.", started);

        boolean update1 = lazySodium.cryptoSignUpdate(state, messageBytes, messageBytes.length);
        assertTrue("First cryptoSignUpdate did not work.", update1);

        boolean update2 = lazySodium.cryptoSignUpdate(state, messageBytes, messageBytes.length);
        assertTrue("Second cryptoSignUpdate did not work.", update2);

        byte[] signature = new byte[Hash.SHA512_BYTES];
        boolean createdSignature = lazySodium.cryptoSignFinalCreate(state, signature, null, sk.getAsBytes());
        assertTrue("cryptoSignFinalCreate unsuccessful", createdSignature);

        boolean verified = lazySodium.cryptoSignFinalVerify(state, signature, pk.getAsBytes());
        assertTrue("cryptoSignFinalVerify did not work", verified);
    }

}
