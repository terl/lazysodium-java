/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.BaseChecker;
import com.goterl.lazysodium.utils.DetachedDecrypt;
import com.goterl.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;

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
        NONCEBYTES = CURVE25519XSALSA20POLY1305_NONCEBYTES,
        SEALBYTES = PUBLICKEYBYTES + MACBYTES;




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

        public static boolean checkNonce(int len) {
            return NONCEBYTES == len;
        }

    }




    interface Native {

        boolean cryptoBoxKeypair(byte[] publicKey, byte[] secretKey);

        boolean cryptoBoxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);

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
                                            long cipherTextLen,
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
                                            long cipherTextLen,
                                            byte[] nonce,
                                            byte[] key);



        boolean cryptoBoxSeal(byte[] cipher, byte[] message, long messageLen, byte[] publicKey);

        boolean cryptoBoxSealOpen(byte[] m,
                                    byte[] cipher,
                                    long cipherLen,
                                    byte[] publicKey,
                                    byte[] secretKey);

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


        /**
         * If you send several messages to the same receiver or receive several messages from the
         * same sender, you can gain speed by calculating
         * the shared key only once, and reusing it in subsequent operations.
         * @param publicKey A public key as generated by {@link #cryptoBoxKeypair()}.
         * @param secretKey A secret key as generated by {@link #cryptoBoxKeypair()}.
         * @return The shared secret key.
         * @throws SodiumException Incorrect key lengths.
         */
        String cryptoBoxBeforeNm(byte[] publicKey, byte[] secretKey) throws SodiumException;

        /**
         * If you send several messages to the same receiver or receive several messages from the
         * same sender, you can gain speed by calculating
         * the shared key only once, and reusing it in subsequent operations.
         * @param keyPair A public and secret key as generated by {@link #cryptoBoxKeypair()}.
         * @return The shared secret key.
         * @throws SodiumException Incorrect key lengths.
         */
        String cryptoBoxBeforeNm(KeyPair keyPair) throws SodiumException;


        /**
         * Encrypt a message.
         * @param message The message for encryption.
         * @param nonce A randomly generated nonce via {@link Random#nonce(int)}}.
         * @param sharedSecretKey The shared secret key as generated via {@link #cryptoBoxBeforeNm(KeyPair)}.
         * @return The encrypted message.
         * @throws SodiumException Incorrect key lengths or enc error.
         */
        String cryptoBoxEasyAfterNm(
                String message,
                byte[] nonce,
                String sharedSecretKey
        ) throws SodiumException;

        /**
         * Decrypt a message.
         * @param cipher The cipher text to be decrypted.
         * @param nonce The same nonce used to encrypt the {@code cipher} - {@link #cryptoBoxEasyAfterNm(String, byte[], String)}.
         * @param sharedSecretKey The shared secret key as generated via {@link #cryptoBoxBeforeNm(KeyPair)}.
         * @return The decrypted message.
         * @throws SodiumException Incorrect key lengths or decryption error.
         */
        String cryptoBoxOpenEasyAfterNm(
                String cipher,
                byte[] nonce,
                String sharedSecretKey
        ) throws SodiumException;

        /**
         * Encrypt a message but allow for storage of
         * the mac separately.
         * @param message The message to encrypt.
         * @param nonce A randomly generated nonce via {@link Random#nonce(int)}}.
         * @param sharedSecretKey The shared secret key as generated via {@link #cryptoBoxBeforeNm(KeyPair)}.
         * @return The encrypted message.
         * @throws SodiumException Incorrect key lengths or enc error.
         */
        DetachedEncrypt cryptoBoxDetachedAfterNm(String message, byte[] nonce, String sharedSecretKey) throws SodiumException;

        /**
         * Decrypt a message.
         * @param detachedEncrypt The cipher and mac used to decrypted the message.
         * @param nonce The same nonce used to encrypt - {@link #cryptoBoxDetachedAfterNm(String, byte[], String)}}.
         * @param sharedSecretKey The shared secret key as generated via {@link #cryptoBoxBeforeNm(KeyPair)}.
         * @return The decrypted message with the {@code mac}.
         * @throws SodiumException Incorrect key lengths or decryption error.
         */
        DetachedDecrypt cryptoBoxOpenDetachedAfterNm(DetachedEncrypt detachedEncrypt,
                                                     byte[] nonce,
                                                     String sharedSecretKey) throws SodiumException;


        /**
         * Encrypts a message.
         * @param message The message.
         * @param publicKey A public key.
         * @return The encrypted {@link Helpers.Lazy#sodiumBin2Hex(byte[])}'ified cipher text.
         */
        String cryptoBoxSealEasy(String message, Key publicKey) throws SodiumException;

        /**
         * Decrypts a previously encrypted message.
         * @param cipherText Encrypted via {@link #cryptoBoxSealEasy(String, Key)}
         *                   and then {@link Helpers.Lazy#sodiumBin2Hex(byte[])}'ified.
         * @param keyPair A keypair.
         * @return The message.
         */
        String cryptoBoxSealOpenEasy(String cipherText, KeyPair keyPair) throws SodiumException;
    }


}
