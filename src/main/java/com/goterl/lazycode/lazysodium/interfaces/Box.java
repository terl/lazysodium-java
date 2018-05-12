/*
 * Copyright (c) Terl Tech Ltd • 11/05/18 23:26 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.BaseChecker;
import com.goterl.lazycode.lazysodium.utils.KeyPair;

public interface Box {


    int CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32,
        CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32,
        CURVE25519XSALSA20POLY1305_MACBYTES = 16,
        CURVE25519XSALSA20POLY1305_SEEDBYTES = 32,
        CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32,
        CURVE25519XSALSA20POLY1305_NONCEBYTES = 24;

    int PUBLICKEYBYTES = CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES,
        SECRETKEYBYTES = CURVE25519XSALSA20POLY1305_SECRETKEYBYTES,
        MACBYTES = CURVE25519XSALSA20POLY1305_MACBYTES,
        SEEDBYTES = CURVE25519XSALSA20POLY1305_SEEDBYTES,
        BEFORENMBYTES = CURVE25519XSALSA20POLY1305_BEFORENMBYTES,
        NONCEBYTES = CURVE25519XSALSA20POLY1305_NONCEBYTES;




    class Checker extends BaseChecker {

        public static boolean checkPublicKey(int len) {
            return PUBLICKEYBYTES == len;
        }

        public static boolean checkMac(int len) {
            return MACBYTES == len;
        }

        public static boolean checkSecretKey(int len) {
            return SECRETKEYBYTES == len;
        }

        public static boolean checkSeed(int len) {
            return SEEDBYTES == len;
        }

        public static boolean checkBeforeNmBytes(int len) {
            return BEFORENMBYTES == len;
        }

    }




    interface Native {

        boolean cryptoBoxKeypair(byte[] publicKey, byte[] secretKey);

        boolean cryptoBoxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);

        boolean cryptoScalarMultBase(byte[] publicKey, byte[] secretKey);

        boolean cryptoBoxEasy(
                byte[] cipherText,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] publicKey,
                byte[] secretKey
        );

        boolean cryptoBoxOpenEasy(
                byte[] message,
                byte[] cipherText,
                long cipherTextLen,
                byte[] nonce,
                byte[] publicKey,
                byte[] secretKey
        );

        boolean cryptoBoxDetached(byte[] cipherText,
                                       byte[] mac,
                                       byte[] message,
                                       long messageLen,
                                       byte[] nonce,
                                       byte[] publicKey,
                                       byte[] secretKey);

        boolean cryptoBoxOpenDetached(byte[] message,
                                            byte[] cipherText,
                                            byte[] mac,
                                            byte[] cipherTextLen,
                                            byte[] nonce,
                                            byte[] publicKey,
                                            byte[] secretKey);

        boolean cryptoBoxBeforeNm(byte[] k, byte[] publicKey, byte[] secretKey);


        boolean cryptoBoxEasyAfterNm(
                byte[] cipherText,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoBoxOpenEasyAfterNm(
                byte[] message, byte[] cipher,
                long cLen, byte[] nonce,
                byte[] key
        );

        boolean cryptoBoxDetachedAfterNm(
                byte[] cipherText,
                byte[] mac,
                byte[] message,
                long messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoBoxOpenDetachedAfterNm(byte[] message,
                                            byte[] cipherText,
                                            byte[] mac,
                                            byte[] cipherTextLen,
                                            byte[] nonce,
                                            byte[] key);


    }

    interface Lazy {

        /**
         * Generate a secret and public key.
         * @return Secret and public key.
         */
        KeyPair cryptoBoxKeypair() throws SodiumException;

        /**
         * Generate a public and secret key deterministically.
         * @param seed The seed to generate the key.
         * @return Public and secret key.
         */
        KeyPair cryptoBoxSeedKeypair(byte[] seed) throws SodiumException;

        /**
         * Generate a public key from a private key.
         * @param secretKey Provide the secret key.
         * @return The public key and the provided secret key.
         */
        KeyPair cryptoScalarMultBase(byte[] secretKey) throws SodiumException;

        /**
         * Generate a public key from a private key.
         * @param secretKey Provide the secret key that's been
         *                  through {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         * @return The public key and the provided secret key.
         */
        KeyPair cryptoScalarMultBase(String secretKey) throws SodiumException;

        /**
         * Encrypts a message.
         * @param message The message.
         * @param nonce The nonce of size {@link #NONCEBYTES}.
         * @param keyPair A keypair.
         * @return The encrypted {@link Helpers.Lazy#sodiumBin2Hex(byte[])}'ified cipher text.
         */
        String cryptoBoxEasy(String message, byte[] nonce, KeyPair keyPair) throws SodiumException;

        /**
         * Decrypts a previously encrypted message.
         * @param cipherText Encrypted via {@link #cryptoBoxEasy(String, byte[], KeyPair)}
         *                   and then {@link Helpers.Lazy#sodiumBin2Hex(byte[])}'ified.
         * @param nonce The nonce of size {@link #NONCEBYTES}.
         * @param keyPair A keypair.
         * @return The message.
         */
        String cryptoBoxOpenEasy(String cipherText, byte[] nonce, KeyPair keyPair) throws SodiumException;



    }


}
