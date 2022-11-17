/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.SecretStream;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SecretStreamTest extends BaseTest {

    private String message1 = "Arbitrary data to encrypt";
    private String message2 = "split into";
    private String message3 = "three messages";

    @Test
    public void test1() throws SodiumException {
        Key key = lazySodium.cryptoSecretStreamKeygen();

        byte[] header = lazySodium.randomBytesBuf(SecretStream.HEADERBYTES);

        // Start the encryption
        SecretStream.State state = lazySodium.cryptoSecretStreamInitPush(header, key);

        String c1 = lazySodium.cryptoSecretStreamPush(state, message1, SecretStream.TAG_MESSAGE);
        String c2 = lazySodium.cryptoSecretStreamPush(state, message2, SecretStream.TAG_MESSAGE);
        String c3 = lazySodium.cryptoSecretStreamPush(state, message3, SecretStream.TAG_FINAL);

        // Start the decryption
        byte[] tag = new byte[1];

        SecretStream.State state2 = lazySodium.cryptoSecretStreamInitPull(header, key);

        String decryptedMessage = lazySodium.cryptoSecretStreamPull(state2, c1, tag);
        String decryptedMessage2 = lazySodium.cryptoSecretStreamPull(state2, c2, tag);
        String decryptedMessage3 = lazySodium.cryptoSecretStreamPull(state2, c3, tag);

        if (tag[0] == SecretStream.XCHACHA20POLY1305_TAG_FINAL) {
            assertTrue(
                    decryptedMessage.equals(message1) &&
                    decryptedMessage2.equals(message2) &&
                    decryptedMessage3.equals(message3)
            );
        }

    }




}
