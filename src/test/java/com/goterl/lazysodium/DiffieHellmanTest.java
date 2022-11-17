/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.DiffieHellman;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DiffieHellmanTest extends BaseTest {

    private String clientSecretKey = "CLIENT_TOP_SECRET_KEY_1234567890";
    private String serverSecretKey = "SERVER_TOP_SECRET_KEY_1234567890";


    @Test
    public void create() throws SodiumException {
        DiffieHellman.Lazy dh = (DiffieHellman.Lazy) lazySodium;
        SecretBox.Lazy box = (SecretBox.Lazy) lazySodium;

        Key secretKeyC = Key.fromPlainString(clientSecretKey);
        Key publicKeyC = dh.cryptoScalarMultBase(secretKeyC);

        Key secretKeyS = Key.fromPlainString(serverSecretKey);
        Key publicKeyS = dh.cryptoScalarMultBase(secretKeyS);

        // -----
        // ON THE CLIENT
        // -----

        // Compute a shared key for sending from client
        // to server.
        Key sharedKey = dh.cryptoScalarMult(secretKeyC, publicKeyS);

        String message = "Hello";
        byte[] nonce = new byte[Box.NONCEBYTES];
        String encrypted = box.cryptoSecretBoxEasy(message, nonce, sharedKey);

        // Send 'encrypted' to server...


        // -----
        // ON THE SERVER
        // -----

        // Compute the shared key for receiving server messages from client
        Key sharedKeyServer = dh.cryptoScalarMult(secretKeyS, publicKeyC);
        String decrypted = box.cryptoSecretBoxOpenEasy(encrypted, nonce, sharedKeyServer);

        // 'decrypted' == Hello

        assertEquals(message, decrypted);
    }
}
