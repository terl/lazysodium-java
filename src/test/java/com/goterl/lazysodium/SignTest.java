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
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SignTest extends BaseTest {


    private Sign.Lazy cryptoSignLazy;

    @BeforeAll
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

        assertNotNull(resultingMessage);
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
        int started = lazySodium.getSodium().crypto_sign_init(state);
        assertTrue(started == 0, "cryptoSignInit not started successfully.");

        boolean update1 = lazySodium.cryptoSignUpdate(state, messageBytes, messageBytes.length);
        assertTrue(update1, "First cryptoSignUpdate did not work.");

        boolean update2 = lazySodium.cryptoSignUpdate(state, messageBytes, messageBytes.length);
        assertTrue(update2, "Second cryptoSignUpdate did not work.");

        // Clone the state now as cryptoSignFinalCreate zeroes
        // all the values.
        Sign.StateCryptoSign clonedState = state.clone();

        byte[] signature = new byte[Hash.SHA512_BYTES];
        boolean createdSignature = lazySodium.cryptoSignFinalCreate(state, signature, null, sk.getAsBytes());
        assertTrue(createdSignature, "cryptoSignFinalCreate unsuccessful");

        boolean verified = lazySodium.cryptoSignFinalVerify(clonedState, signature, pk.getAsBytes());
        assertTrue(verified, "cryptoSignFinalVerify did not work");
    }

}
