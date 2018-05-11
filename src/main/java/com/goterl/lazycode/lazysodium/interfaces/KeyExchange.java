/*
 * Copyright (c) Terl Tech Ltd • 09/05/18 01:25 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.LazySodium;
import com.goterl.lazycode.lazysodium.Sodium;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;

public interface KeyExchange {

    int PUBLICKEYBYTES = 32;
    int SECRETKEYBYTES = 32;
    int SESSIONKEYBYTES = 32;
    int SEEDBYTES = 32;
    String PRIMITIVE = "x25519blake2b";


    class KeyPair {
        private byte[] secretKey;
        private byte[] publicKey;

        public KeyPair(byte[] publicKey, byte[] secretKey) {
            this.secretKey = secretKey;
            this.publicKey = publicKey;
        }

        public KeyPair(String publicKey, String secretKey) {
            this.secretKey = LazySodium.toBin(secretKey);
            this.publicKey = LazySodium.toBin(publicKey);
        }

        public byte[] getSecretKey() {
            return secretKey;
        }

        public byte[] getPublicKey() {
            return publicKey;
        }

        public String getSecretKeyString() {
            return LazySodium.toHex(secretKey);
        }

        public String getPublicKeyString() {
            return LazySodium.toHex(publicKey);
        }
    }

    class SessionPair {
        private byte[] rx;
        private byte[] tx;

        public SessionPair(byte[] rx, byte[] tx) {
            this.rx = rx;
            this.tx = tx;
        }

        public SessionPair(String rx, String tx) {
            this.rx = LazySodium.toBin(rx);
            this.tx =  LazySodium.toBin(tx);
        }

        public byte[] getRx() {
            return rx;
        }

        public byte[] getTx() {
            return tx;
        }

        public String getRxString() {
            return LazySodium.toHex(rx);
        }

        public String getTxString() {
            return LazySodium.toHex(tx);
        }
    }

    interface Native {
        boolean cryptoKxKeypair(byte[] publicKey, byte[] secretKey);
        boolean cryptoKxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);
        boolean cryptoKxClientSessionKeys(
                byte[] rx,
                byte[] tx,
                byte[] clientPk,
                byte[] clientSk,
                byte[] serverPk
        );
        boolean cryptoKxServerSessionKeys(
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
        ) throws SodiumException;

        SessionPair cryptoKxClientSessionKeys(
                KeyPair clientKeyPair,
                KeyPair serverKeyPair
        ) throws SodiumException;

        SessionPair cryptoKxServerSessionKeys(
                byte[] serverPk,
                byte[] serverSk,
                byte[] clientPk
        ) throws SodiumException;

        SessionPair cryptoKxServerSessionKeys(
                KeyPair serverKeyPair,
                KeyPair clientKeyPair
        ) throws SodiumException;
    }


}
