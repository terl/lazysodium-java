/*
 * Copyright (c) Terl Tech Ltd • 09/05/18 01:25 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


public interface KeyExchange {

    int PUBLICKEYBYTES = 32;
    int SECRETKEYBYTES = 32;
    int SESSIONKEYBYTES = 32;
    int SEEDBYTES = 32;
    String PRIMITIVE = "x25519blake2b";


    class KeyPair {
        private String secretKey;
        private String publicKey;

        public KeyPair(String publicKey, String secretKey) {
            this.secretKey = secretKey;
            this.publicKey = publicKey;
        }

        public String getSecretKey() {
            return secretKey;
        }

        public String getPublicKey() {
            return publicKey;
        }
    }

    class SessionPair {
        private String rx;
        private String tx;

        public SessionPair(String rx, String tx) {
            this.rx = rx;
            this.tx = tx;
        }

        public String getRx() {
            return rx;
        }

        public String getTx() {
            return tx;
        }
    }

    interface Native {
        int cryptoKxKeypair(byte[] publicKey, byte[] secretKey);
        int cryptoKxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);
        int cryptoKxClientSessionKeys(
                byte[] rx,
                byte[] tx,
                byte[] clientPk,
                byte[] clientSk,
                byte[] serverPk
        );
        int cryptoKxServerSessionKeys(
                byte[] rx,
                byte[] tx,
                byte[] serverPk,
                byte[] serverSk,
                byte[] clientPk
        );
    }

    interface Lazy {
        KeyPair cryptoKxKeypair();
        KeyPair cryptoKxKeypair(byte[] seed);
        SessionPair cryptoKxClientSessionKeys(
                byte[] clientPk,
                byte[] clientSk,
                byte[] serverPk
        );
        SessionPair cryptoKxServerSessionKeys(
                byte[] serverPk,
                byte[] serverSk,
                byte[] clientPk
        );
    }


}
