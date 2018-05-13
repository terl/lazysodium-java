/*
 * Copyright (c) Terl Tech Ltd • 07/05/18 10:34 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public interface SecretStream {

    int XCHACHA20POLY1305_KEYBYTES = AEAD.XCHACHA20POLY1305_IETF_KEYBYTES,
        XCHACHA20POLY1305_ABYTES = AEAD.XCHACHA20POLY1305_IETF_ABYTES + 1,
        XCHACHA20POLY1305_HEADERBYTES = AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES;

    byte XCHACHA20POLY1305_TAG_PUSH = 0x01;
    byte XCHACHA20POLY1305_TAG_REKEY = 0x02;
    byte XCHACHA20POLY1305_TAG_FINAL = XCHACHA20POLY1305_TAG_PUSH | XCHACHA20POLY1305_TAG_REKEY;



    interface Native {

        void cryptoSecretStreamXChacha20Poly1305Keygen(byte[] key);

        int cryptoSecretStreamXChacha20Poly1305InitPush(
                State state,
                byte[] header,
                byte[] key
        );

        int cryptoSecretStreamXChacha20Poly1305Push(
                State state,
                byte[] cipher,
                Long cipherAddr,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte tag
        );

        int cryptoSecretStreamXChacha20Poly1305Push(
                State state,
                byte[] cipher,
                Long cipherAddr,
                byte[] message,
                long messageLen,
                byte tag
        );

        int cryptoSecretStreamXChacha20Poly1305Push(
                State state,
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte tag
        );


        int cryptoSecretStreamXChacha20Poly1305InitPull(
                State state,
                byte[] header,
                byte[] key
        );


        int cryptoSecretStreamXChacha20Poly1305Pull(
                State state,
                byte[] message,
                Long messageAddress,
                byte tag,
                byte[] cipher,
                long cipherLen,
                byte[] additionalData,
                long additionalDataLen
        );

        int cryptoSecretStreamXChacha20Poly1305Pull(
                State state,
                byte[] message,
                byte tag,
                byte[] cipher,
                long cipherLen
        );


    }

    interface Lazy {

    }


    class State extends Structure {

        public static class ByReference extends State implements Structure.ByReference { }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("k", "_pad");
        }

        public char[] k = new char[XCHACHA20POLY1305_KEYBYTES];
        public char[] _pad = new char[8];

    }
}
